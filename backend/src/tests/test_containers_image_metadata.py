"""Unit tests for container image-metadata extraction and scanner enrichment."""
from __future__ import annotations

import os

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost:5432/test")
os.environ.setdefault("RUNNER_ENCRYPTION_KEY", "0" * 64)

from src.containers.image_metadata import extract_image_metadata  # noqa: E402
from src.containers.scanner import _apply_image_enrichment  # noqa: E402


def _cyclonedx_with_distro(distro_id: str = "alpine", version: str = "3.18.0") -> dict:
    """Minimal CycloneDX shape matching what Syft emits for a container image."""
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "metadata": {
            "component": {
                "type": "container",
                "name": "registry/example",
                "version": "v1",
            }
        },
        "components": [
            {
                "type": "operating-system",
                "name": distro_id,
                "swid": {"tagId": distro_id, "name": distro_id, "version": version},
                "properties": [
                    {"name": "syft:distro:id", "value": distro_id},
                    {"name": "syft:distro:versionID", "value": version},
                    {"name": "syft:distro:prettyName", "value": f"{distro_id} {version}"},
                ],
            }
        ],
    }


def _syft_json(image_size: int = 12_345_678, layer_count: int = 4) -> dict:
    return {
        "source": {
            "metadata": {
                "imageSize": image_size,
                "layers": [
                    {"digest": f"sha256:{i:064x}", "size": image_size // layer_count}
                    for i in range(layer_count)
                ],
            }
        }
    }


def test_extract_image_metadata_returns_all_three_fields():
    out = extract_image_metadata(_syft_json(), _cyclonedx_with_distro())
    assert out == {
        "layerCount": 4,
        "sizeBytes": 12_345_678,
        "baseOs": "alpine:3.18.0",
    }


def test_extract_image_metadata_returns_nulls_for_empty_inputs():
    out = extract_image_metadata(None, None)
    assert out == {"layerCount": None, "sizeBytes": None, "baseOs": None}


def test_extract_image_metadata_falls_back_to_pretty_name_when_id_missing():
    sbom = {
        "components": [
            {
                "type": "operating-system",
                "properties": [
                    {"name": "syft:distro:prettyName", "value": "Custom Distro 1.2"},
                ],
            }
        ]
    }
    out = extract_image_metadata(None, sbom)
    assert out["baseOs"] == "Custom Distro 1.2"


def test_extract_image_metadata_rejects_non_int_size():
    syft = {"source": {"metadata": {"imageSize": "12345"}}}
    assert extract_image_metadata(syft, None)["sizeBytes"] is None


def test_extract_image_metadata_handles_missing_os_component():
    sbom = {"components": [{"type": "library", "name": "foo"}]}
    assert extract_image_metadata(None, sbom)["baseOs"] is None


def test_extract_image_metadata_rejects_bool_size_bytes():
    syft = {"source": {"metadata": {"imageSize": True}}}
    assert extract_image_metadata(syft, None)["sizeBytes"] is None


def test_apply_image_enrichment_matches_by_digest():
    findings = [
        {"imageDigest": "sha256:abc", "packageName": "openssl"},
        {"imageDigest": "sha256:xyz", "packageName": "curl"},
    ]
    image_sboms = {
        "img1": {
            "digest": "sha256:abc",
            "sbom": _cyclonedx_with_distro(),
            "syft_json": _syft_json(image_size=999, layer_count=3),
        },
    }
    _apply_image_enrichment(findings, image_sboms)
    assert findings[0]["layerCount"] == 3
    assert findings[0]["sizeBytes"] == 999
    assert findings[0]["baseOs"] == "alpine:3.18.0"
    # Unmatched finding stays untouched.
    assert "layerCount" not in findings[1]


def test_apply_image_enrichment_noop_when_all_extracted_fields_null():
    findings = [{"imageDigest": "sha256:abc"}]
    image_sboms = {
        "img1": {"digest": "sha256:abc", "sbom": None, "syft_json": None},
    }
    _apply_image_enrichment(findings, image_sboms)
    assert "layerCount" not in findings[0]


def test_apply_image_enrichment_falls_back_to_commit_sha():
    findings = [{"commit_sha": "sha256:fallback", "packageName": "zlib"}]
    image_sboms = {
        "img1": {
            "digest": "sha256:fallback",
            "sbom": _cyclonedx_with_distro("debian", "12"),
            "syft_json": _syft_json(image_size=1024, layer_count=2),
        },
    }
    _apply_image_enrichment(findings, image_sboms)
    assert findings[0]["baseOs"] == "debian:12"
    assert findings[0]["layerCount"] == 2
