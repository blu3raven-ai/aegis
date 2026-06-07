"""Extract image-level metadata (layers, size, base OS) from scanner output blobs.

The runner emits two artifacts per scanned image:

* ``sbom.cdx.json`` — CycloneDX JSON (consumed by Grype and downstream tools)
* ``sbom.syft.json`` — Syft's native JSON, which carries ``source.metadata``
  including ``imageSize`` and a per-layer breakdown that CycloneDX drops.

This module is intentionally pure (no I/O) so the ingest path and tests can
feed it pre-loaded dicts.
"""
from __future__ import annotations

from typing import Any


def extract_image_metadata(
    syft_json: dict[str, Any] | None,
    cyclonedx_sbom: dict[str, Any] | None,
) -> dict[str, Any]:
    """Return ``{layerCount, sizeBytes, baseOs}`` with ``None`` for any field
    that the inputs do not surface.

    Both inputs are optional so callers can pass whichever blobs they have.
    """
    return {
        "layerCount": _layer_count(syft_json),
        "sizeBytes": _size_bytes(syft_json),
        "baseOs": _base_os(cyclonedx_sbom),
    }


def _syft_image_metadata(syft_json: dict[str, Any] | None) -> dict[str, Any] | None:
    if not isinstance(syft_json, dict):
        return None
    source = syft_json.get("source")
    if not isinstance(source, dict):
        return None
    metadata = source.get("metadata")
    return metadata if isinstance(metadata, dict) else None


def _layer_count(syft_json: dict[str, Any] | None) -> int | None:
    metadata = _syft_image_metadata(syft_json)
    if metadata is None:
        return None
    layers = metadata.get("layers")
    if isinstance(layers, list):
        return len(layers)
    return None


def _size_bytes(syft_json: dict[str, Any] | None) -> int | None:
    metadata = _syft_image_metadata(syft_json)
    if metadata is None:
        return None
    size = metadata.get("imageSize")
    if isinstance(size, bool):  # bool is an int subclass — reject it explicitly
        return None
    if isinstance(size, int) and size >= 0:
        return size
    return None


def _base_os(cyclonedx_sbom: dict[str, Any] | None) -> str | None:
    """Derive ``id:version`` from the SBOM's operating-system component.

    Syft emits a dedicated ``operating-system`` component carrying both a SWID
    (id/version) and ``syft:distro:*`` properties. We prefer the property pair
    because it preserves Syft's normalized id (e.g. ``alpine``) and version,
    and fall back to the SWID name/version, then to ``syft:distro:prettyName``.
    """
    if not isinstance(cyclonedx_sbom, dict):
        return None
    os_component = _find_os_component(cyclonedx_sbom)
    if os_component is None:
        return None

    properties = _properties_dict(os_component.get("properties"))
    distro_id = properties.get("syft:distro:id")
    version_id = properties.get("syft:distro:versionID")
    if distro_id and version_id:
        return f"{distro_id}:{version_id}"

    swid = os_component.get("swid") or {}
    swid_name = swid.get("name") if isinstance(swid, dict) else None
    swid_version = swid.get("version") if isinstance(swid, dict) else None
    if swid_name and swid_version:
        return f"{swid_name}:{swid_version}"

    pretty = properties.get("syft:distro:prettyName")
    if pretty:
        return pretty
    return None


def _find_os_component(cyclonedx_sbom: dict[str, Any]) -> dict[str, Any] | None:
    components = cyclonedx_sbom.get("components")
    if not isinstance(components, list):
        return None
    for comp in components:
        if isinstance(comp, dict) and comp.get("type") == "operating-system":
            return comp
    return None


def _properties_dict(properties: Any) -> dict[str, str]:
    out: dict[str, str] = {}
    if not isinstance(properties, list):
        return out
    for entry in properties:
        if not isinstance(entry, dict):
            continue
        name = entry.get("name")
        value = entry.get("value")
        if isinstance(name, str) and isinstance(value, str):
            out[name] = value
    return out
