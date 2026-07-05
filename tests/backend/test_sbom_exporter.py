"""Unit tests for SbomExporter — all format conversions.

Uses small hand-built CycloneDX JSON fixtures; no database or MinIO needed.
"""
from __future__ import annotations

import json
import xml.etree.ElementTree as ET

import pytest

from src.sbom.exporter import SbomExporter, UnsupportedFormatError, SUPPORTED_FORMATS


# ── Fixtures ──────────────────────────────────────────────────────────────────

MINIMAL_SBOM: dict = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.4",
    "version": 1,
    "serialNumber": "urn:uuid:test-0000",
    "metadata": {
        "timestamp": "2024-01-15T10:00:00Z",
        "tools": [{"name": "syft", "version": "1.0.0"}],
    },
    "components": [
        {
            "type": "library",
            "bom-ref": "pkg:npm/lodash@4.17.21",
            "name": "lodash",
            "version": "4.17.21",
            "purl": "pkg:npm/lodash@4.17.21",
            "licenses": [{"license": {"id": "MIT"}}],
        },
        {
            "type": "library",
            "bom-ref": "pkg:npm/express@4.18.0",
            "name": "express",
            "version": "4.18.0",
            "purl": "pkg:npm/express@4.18.0",
        },
    ],
    "dependencies": [
        {
            "ref": "pkg:npm/express@4.18.0",
            "dependsOn": ["pkg:npm/lodash@4.17.21"],
        }
    ],
}

EMPTY_SBOM: dict = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.4",
    "components": [],
}


@pytest.fixture
def exporter() -> SbomExporter:
    return SbomExporter()


# ── SUPPORTED_FORMATS constant ────────────────────────────────────────────────

def test_supported_formats_contains_four_values():
    assert len(SUPPORTED_FORMATS) == 4
    assert "cyclonedx-json" in SUPPORTED_FORMATS
    assert "cyclonedx-xml" in SUPPORTED_FORMATS
    assert "spdx-json" in SUPPORTED_FORMATS
    assert "spdx-tag-value" in SUPPORTED_FORMATS


# ── cyclonedx-json (passthrough) ──────────────────────────────────────────────

def test_cyclonedx_json_passthrough(exporter):
    result = exporter.export(MINIMAL_SBOM, "cyclonedx-json")
    parsed = json.loads(result)
    assert parsed["bomFormat"] == "CycloneDX"
    assert len(parsed["components"]) == 2
    assert parsed["components"][0]["name"] == "lodash"


def test_cyclonedx_json_preserves_all_top_level_keys(exporter):
    result = exporter.export(MINIMAL_SBOM, "cyclonedx-json")
    parsed = json.loads(result)
    for key in ("bomFormat", "specVersion", "metadata", "components", "dependencies"):
        assert key in parsed, f"Expected top-level key '{key}' missing from output"


def test_cyclonedx_json_empty_sbom(exporter):
    result = exporter.export(EMPTY_SBOM, "cyclonedx-json")
    parsed = json.loads(result)
    assert parsed["components"] == []


# ── cyclonedx-xml ─────────────────────────────────────────────────────────────

def test_cyclonedx_xml_is_valid_xml(exporter):
    result = exporter.export(MINIMAL_SBOM, "cyclonedx-xml")
    assert result.startswith("<?xml")
    # Must parse without error
    root = ET.fromstring(result.split("\n", 1)[1])
    assert root is not None


def test_cyclonedx_xml_contains_components(exporter):
    result = exporter.export(MINIMAL_SBOM, "cyclonedx-xml")
    assert "lodash" in result
    assert "express" in result


def test_cyclonedx_xml_contains_version(exporter):
    result = exporter.export(MINIMAL_SBOM, "cyclonedx-xml")
    assert "4.17.21" in result


def test_cyclonedx_xml_has_bom_root_element(exporter):
    result = exporter.export(MINIMAL_SBOM, "cyclonedx-xml")
    root = ET.fromstring(result.split("\n", 1)[1])
    assert "bom" in root.tag


def test_cyclonedx_xml_metadata_timestamp(exporter):
    result = exporter.export(MINIMAL_SBOM, "cyclonedx-xml")
    assert "2024-01-15T10:00:00Z" in result


def test_cyclonedx_xml_empty_sbom_no_components_element(exporter):
    result = exporter.export(EMPTY_SBOM, "cyclonedx-xml")
    # No <components> element when the list is empty
    assert "<components" not in result


def test_cyclonedx_xml_license_in_component(exporter):
    result = exporter.export(MINIMAL_SBOM, "cyclonedx-xml")
    assert "MIT" in result


# ── spdx-json ─────────────────────────────────────────────────────────────────

def test_spdx_json_is_valid_json(exporter):
    result = exporter.export(MINIMAL_SBOM, "spdx-json")
    parsed = json.loads(result)
    assert parsed is not None


def test_spdx_json_has_required_top_level_fields(exporter):
    result = exporter.export(MINIMAL_SBOM, "spdx-json")
    parsed = json.loads(result)
    for field in ("SPDXID", "spdxVersion", "creationInfo", "name", "dataLicense",
                  "documentNamespace", "packages"):
        assert field in parsed, f"Required SPDX field '{field}' missing"


def test_spdx_json_version_is_2_3(exporter):
    result = exporter.export(MINIMAL_SBOM, "spdx-json")
    parsed = json.loads(result)
    assert parsed["spdxVersion"] == "SPDX-2.3"


def test_spdx_json_data_license_is_cc0(exporter):
    result = exporter.export(MINIMAL_SBOM, "spdx-json")
    parsed = json.loads(result)
    assert parsed["dataLicense"] == "CC0-1.0"


def test_spdx_json_packages_count_matches_components(exporter):
    result = exporter.export(MINIMAL_SBOM, "spdx-json")
    parsed = json.loads(result)
    assert len(parsed["packages"]) == len(MINIMAL_SBOM["components"])


def test_spdx_json_package_fields_present(exporter):
    result = exporter.export(MINIMAL_SBOM, "spdx-json")
    parsed = json.loads(result)
    pkg = parsed["packages"][0]
    for field in ("SPDXID", "name", "versionInfo", "licenseDeclared",
                  "licenseConcluded", "copyrightText", "downloadLocation"):
        assert field in pkg, f"Required package field '{field}' missing"


def test_spdx_json_name_from_metadata_component(exporter):
    sbom = dict(MINIMAL_SBOM)
    sbom["metadata"] = {
        **MINIMAL_SBOM["metadata"],
        "component": {"name": "my-service"},
    }
    result = exporter.export(sbom, "spdx-json")
    parsed = json.loads(result)
    assert parsed["name"] == "my-service"


def test_spdx_json_purl_mapped_to_external_ref(exporter):
    result = exporter.export(MINIMAL_SBOM, "spdx-json")
    parsed = json.loads(result)
    pkg = parsed["packages"][0]
    ext_refs = pkg.get("externalRefs", [])
    assert any(r["referenceType"] == "purl" for r in ext_refs)


def test_spdx_json_license_declared_from_cyclonedx(exporter):
    result = exporter.export(MINIMAL_SBOM, "spdx-json")
    parsed = json.loads(result)
    # lodash is index 0 with MIT license
    assert parsed["packages"][0]["licenseDeclared"] == "MIT"


def test_spdx_json_no_license_defaults_to_noassertion(exporter):
    result = exporter.export(MINIMAL_SBOM, "spdx-json")
    parsed = json.loads(result)
    # express has no licenses in fixture
    assert parsed["packages"][1]["licenseDeclared"] == "NOASSERTION"


def test_spdx_json_depends_on_relationships(exporter):
    result = exporter.export(MINIMAL_SBOM, "spdx-json")
    parsed = json.loads(result)
    rels = parsed["relationships"]
    dep_rels = [r for r in rels if r["relationshipType"] == "DEPENDS_ON"]
    assert len(dep_rels) == 1
    assert dep_rels[0]["spdxElementId"] == "SPDXRef-Package-1"
    assert dep_rels[0]["relatedSpdxElement"] == "SPDXRef-Package-0"


def test_spdx_json_creation_info_creator_from_tools(exporter):
    result = exporter.export(MINIMAL_SBOM, "spdx-json")
    parsed = json.loads(result)
    creators = parsed["creationInfo"]["creators"]
    assert any("syft" in c for c in creators)


def test_spdx_json_creation_info_timestamp(exporter):
    result = exporter.export(MINIMAL_SBOM, "spdx-json")
    parsed = json.loads(result)
    assert parsed["creationInfo"]["created"] == "2024-01-15T10:00:00Z"


def test_spdx_json_empty_sbom_no_packages(exporter):
    result = exporter.export(EMPTY_SBOM, "spdx-json")
    parsed = json.loads(result)
    assert parsed["packages"] == []


# ── spdx-tag-value ────────────────────────────────────────────────────────────

def test_spdx_tag_value_contains_spdx_version(exporter):
    result = exporter.export(MINIMAL_SBOM, "spdx-tag-value")
    assert "SPDXVersion: SPDX-2.3" in result


def test_spdx_tag_value_contains_data_license(exporter):
    result = exporter.export(MINIMAL_SBOM, "spdx-tag-value")
    assert "DataLicense: CC0-1.0" in result


def test_spdx_tag_value_contains_package_names(exporter):
    result = exporter.export(MINIMAL_SBOM, "spdx-tag-value")
    assert "PackageName: lodash" in result
    assert "PackageName: express" in result


def test_spdx_tag_value_contains_package_versions(exporter):
    result = exporter.export(MINIMAL_SBOM, "spdx-tag-value")
    assert "PackageVersion: 4.17.21" in result


def test_spdx_tag_value_contains_relationship(exporter):
    result = exporter.export(MINIMAL_SBOM, "spdx-tag-value")
    assert "Relationship:" in result
    assert "DEPENDS_ON" in result


def test_spdx_tag_value_line_format(exporter):
    result = exporter.export(MINIMAL_SBOM, "spdx-tag-value")
    for line in result.splitlines():
        if not line.strip():
            continue
        # Every non-empty line must be "Key: value"
        assert ": " in line, f"Tag-value line missing ': ' separator: {line!r}"


# ── Error handling ────────────────────────────────────────────────────────────

def test_unknown_format_raises_value_error(exporter):
    with pytest.raises(ValueError, match="Unknown format"):
        exporter.export(MINIMAL_SBOM, "csv")


def test_unknown_format_error_mentions_format_name(exporter):
    with pytest.raises(ValueError, match="csv"):
        exporter.export(MINIMAL_SBOM, "csv")
