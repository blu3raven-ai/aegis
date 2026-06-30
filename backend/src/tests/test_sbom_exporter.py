"""Conversion-correctness tests for the SBOM exporter.

Robustness (no-crash on malformed input) is covered in test_sbom_robustness;
these lock that a well-formed CycloneDX SBOM converts to *correct* output in
each supported format — the export endpoints are ungated for every tier, so a
silent regression here ships broken SBOMs to customers.
"""
from __future__ import annotations

import json
import xml.etree.ElementTree as ET

import pytest

from src.sbom.exporter import SbomExporter


def _sbom() -> dict:
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "serialNumber": "urn:uuid:1111-2222",
        "metadata": {
            "timestamp": "2026-06-01T00:00:00Z",
            "tools": [{"name": "syft", "version": "1.0"}],
            "component": {"name": "my-app", "bom-ref": "root", "type": "application"},
        },
        "components": [
            {"bom-ref": "c1", "type": "library", "name": "lodash", "version": "4.17.21",
             "purl": "pkg:npm/lodash@4.17.21", "licenses": [{"license": {"id": "MIT"}}]},
            {"bom-ref": "c2", "type": "library", "name": "axios", "version": "1.6.0",
             "purl": "pkg:npm/axios@1.6.0"},
        ],
        "dependencies": [{"ref": "root", "dependsOn": ["c1", "c2"]}],
    }


def test_cyclonedx_json_preserves_the_bom():
    doc = json.loads(SbomExporter().export(_sbom(), "cyclonedx-json"))
    assert doc["bomFormat"] == "CycloneDX"
    assert {c["name"]: c["version"] for c in doc["components"]} == {
        "lodash": "4.17.21", "axios": "1.6.0",
    }


def test_cyclonedx_xml_is_well_formed_with_components():
    out = SbomExporter().export(_sbom(), "cyclonedx-xml")
    assert out.startswith("<?xml")
    root = ET.fromstring(out)  # raises on malformed XML
    ns = "{http://cyclonedx.org/schema/bom/1.5}"
    names = {e.text for e in root.iter(f"{ns}name")}
    assert {"lodash", "axios"} <= names
    purls = {e.text for e in root.iter(f"{ns}purl")}
    assert "pkg:npm/lodash@4.17.21" in purls
    # the MIT license rode along
    assert any(e.text == "MIT" for e in root.iter(f"{ns}id"))


def test_spdx_json_is_valid_2_3():
    doc = json.loads(SbomExporter().export(_sbom(), "spdx-json"))
    assert doc["SPDXID"] == "SPDXRef-DOCUMENT"
    assert doc["spdxVersion"] == "SPDX-2.3"
    pkgs = {p["name"]: p for p in doc["packages"]}
    assert pkgs["lodash"]["versionInfo"] == "4.17.21"
    assert pkgs["lodash"]["licenseConcluded"] == "MIT"
    # axios has no declared license -> NOASSERTION, never a crash
    assert pkgs["axios"]["licenseConcluded"] == "NOASSERTION"
    assert any(r["relationshipType"] == "DESCRIBES" for r in doc["relationships"])


def test_spdx_tag_value_has_headers_and_packages():
    out = SbomExporter().export(_sbom(), "spdx-tag-value")
    assert "SPDXVersion: SPDX-2.3" in out
    assert "PackageName: lodash" in out
    assert "PackageVersion: 4.17.21" in out
    assert "PackageName: axios" in out


def test_empty_sbom_still_produces_valid_output_per_format():
    empty = {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": []}
    assert json.loads(SbomExporter().export(empty, "cyclonedx-json"))["components"] == []
    ET.fromstring(SbomExporter().export(empty, "cyclonedx-xml"))
    assert json.loads(SbomExporter().export(empty, "spdx-json"))["SPDXID"] == "SPDXRef-DOCUMENT"
    assert "SPDXVersion:" in SbomExporter().export(empty, "spdx-tag-value")


def test_unknown_format_raises():
    with pytest.raises(ValueError):
        SbomExporter().export(_sbom(), "bogus-format")
