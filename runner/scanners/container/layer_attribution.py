"""Attribute each container SBOM component to the image layer that introduced it.

Syft's CycloneDX output does not say which layer a package came from, but its
native ``syft-json`` output does (each artifact carries ``locations[].layerID``,
and ``source.metadata.layers`` lists the layer digests bottom-to-top). This
reads the syft-json sidecar and stamps the introducing layer's digest and its
0-based ordinal onto the matching CycloneDX components as ``aegis:*`` properties,
so the backend picks them up through the same channel it already uses for
declared-range metadata — no second file to ingest.
"""
from __future__ import annotations

import json
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

_LAYER_DIGEST_PROPERTY = "aegis:layer_digest"
_LAYER_INDEX_PROPERTY = "aegis:layer_index"


def _layer_order(syft: dict) -> dict[str, int]:
    """Map each layer digest to its 0-based ordinal (bottom-most layer = 0)."""
    layers = ((syft.get("source") or {}).get("metadata") or {}).get("layers")
    order: dict[str, int] = {}
    if isinstance(layers, list):
        for idx, layer in enumerate(layers):
            if isinstance(layer, dict):
                digest = layer.get("digest")
                if isinstance(digest, str) and digest:
                    order.setdefault(digest, idx)
    return order


def _purl_to_layer(syft: dict) -> dict[str, str]:
    """Map each artifact purl to the digest of the layer that introduced it.

    A package can appear in several locations; the first with a layerID wins —
    that is where its metadata was installed (the introducing layer)."""
    out: dict[str, str] = {}
    artifacts = syft.get("artifacts")
    if not isinstance(artifacts, list):
        return out
    for art in artifacts:
        if not isinstance(art, dict):
            continue
        purl = art.get("purl")
        if not isinstance(purl, str) or not purl:
            continue
        for loc in art.get("locations") or []:
            layer_id = loc.get("layerID") if isinstance(loc, dict) else None
            if isinstance(layer_id, str) and layer_id:
                out.setdefault(purl, layer_id)
                break
    return out


def _stamp(props: list, name: str, value: str) -> None:
    props.append({"name": name, "value": value})


def annotate_sbom_with_layers(sbom_path: Path, syft_json_path: Path) -> int:
    """Stamp introducing-layer digest + ordinal onto CycloneDX components.

    Matches CycloneDX components to syft artifacts by purl. Fully guarded: a
    missing/unreadable/oddly-shaped file on either side yields 0 rather than
    raising. Idempotent — components already carrying the layer digest are left
    alone. Returns the number of components annotated."""
    try:
        syft = json.loads(syft_json_path.read_text())
        data = json.loads(sbom_path.read_text())
    except (OSError, ValueError, TypeError):
        return 0
    if not isinstance(syft, dict) or not isinstance(data, dict):
        return 0
    components = data.get("components")
    if not isinstance(components, list):
        return 0

    purl_layer = _purl_to_layer(syft)
    if not purl_layer:
        return 0
    layer_order = _layer_order(syft)

    annotated = 0
    for component in components:
        if not isinstance(component, dict):
            continue
        purl = component.get("purl")
        layer_id = purl_layer.get(purl) if isinstance(purl, str) else None
        if not layer_id:
            continue
        props = component.get("properties")
        if not isinstance(props, list):
            props = []
            component["properties"] = props
        if any(isinstance(p, dict) and p.get("name") == _LAYER_DIGEST_PROPERTY for p in props):
            continue  # idempotent
        _stamp(props, _LAYER_DIGEST_PROPERTY, layer_id)
        if layer_id in layer_order:
            _stamp(props, _LAYER_INDEX_PROPERTY, str(layer_order[layer_id]))
        annotated += 1

    if annotated:
        sbom_path.write_text(json.dumps(data, separators=(",", ":")))
    return annotated
