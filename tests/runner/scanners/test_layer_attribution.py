from __future__ import annotations

import json
from pathlib import Path

from runner.scanners.container.layer_attribution import annotate_sbom_with_layers


def _write(path: Path, obj: dict) -> None:
    path.write_text(json.dumps(obj))


def _props(component: dict) -> dict[str, str]:
    return {p["name"]: p["value"] for p in component.get("properties", [])}


def _syft() -> dict:
    return {
        "artifacts": [
            {
                "name": "openssl", "version": "1.1.1", "purl": "pkg:deb/debian/openssl@1.1.1",
                "locations": [{"path": "/usr/lib/x", "layerID": "sha256:base"}],
            },
            {
                "name": "app", "version": "2.0", "purl": "pkg:npm/app@2.0",
                "locations": [{"path": "/srv/app", "layerID": "sha256:top"}],
            },
        ],
        "source": {"metadata": {"layers": [
            {"digest": "sha256:base"}, {"digest": "sha256:mid"}, {"digest": "sha256:top"},
        ]}},
    }


def _cdx() -> dict:
    return {
        "components": [
            {"name": "openssl", "version": "1.1.1", "purl": "pkg:deb/debian/openssl@1.1.1"},
            {"name": "app", "version": "2.0", "purl": "pkg:npm/app@2.0"},
            {"name": "unlocated", "version": "1.0", "purl": "pkg:npm/unlocated@1.0"},
        ]
    }


def test_stamps_layer_digest_and_index(tmp_path: Path) -> None:
    cdx, syft = tmp_path / "sbom.cdx.json", tmp_path / "sbom.syft.json"
    _write(cdx, _cdx())
    _write(syft, _syft())

    n = annotate_sbom_with_layers(cdx, syft)
    assert n == 2

    by_name = {c["name"]: c for c in json.loads(cdx.read_text())["components"]}
    assert _props(by_name["openssl"]) == {"aegis:layer_digest": "sha256:base", "aegis:layer_index": "0"}
    # top layer is ordinal 2 in the 3-layer stack
    assert _props(by_name["app"]) == {"aegis:layer_digest": "sha256:top", "aegis:layer_index": "2"}
    # a component syft couldn't locate is left untouched
    assert "properties" not in by_name["unlocated"]


def test_idempotent_on_rerun(tmp_path: Path) -> None:
    cdx, syft = tmp_path / "sbom.cdx.json", tmp_path / "sbom.syft.json"
    _write(cdx, _cdx())
    _write(syft, _syft())
    annotate_sbom_with_layers(cdx, syft)
    assert annotate_sbom_with_layers(cdx, syft) == 0  # already stamped
    openssl = next(c for c in json.loads(cdx.read_text())["components"] if c["name"] == "openssl")
    assert len(openssl["properties"]) == 2  # not duplicated


def test_digest_stamped_even_without_layer_order(tmp_path: Path) -> None:
    # No source.metadata.layers → digest still attributed, index omitted.
    syft = {"artifacts": [
        {"purl": "pkg:npm/app@2.0", "locations": [{"layerID": "sha256:x"}]},
    ]}
    cdx, syft_path = tmp_path / "sbom.cdx.json", tmp_path / "sbom.syft.json"
    _write(cdx, {"components": [{"name": "app", "purl": "pkg:npm/app@2.0"}]})
    _write(syft_path, syft)
    assert annotate_sbom_with_layers(cdx, syft_path) == 1
    props = _props(json.loads(cdx.read_text())["components"][0])
    assert props == {"aegis:layer_digest": "sha256:x"}


def test_missing_or_malformed_files_yield_zero(tmp_path: Path) -> None:
    cdx, syft = tmp_path / "sbom.cdx.json", tmp_path / "sbom.syft.json"
    _write(cdx, _cdx())
    assert annotate_sbom_with_layers(cdx, tmp_path / "missing.json") == 0
    syft.write_text("{not json")
    assert annotate_sbom_with_layers(cdx, syft) == 0
