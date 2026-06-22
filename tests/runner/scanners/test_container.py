"""Tests for the embedded container scanner module."""
from __future__ import annotations

import json
import os
import stat
import threading
from pathlib import Path

import pytest


# ---------------------------------------------------------------------------
# Task 3.1 — registry_auth.py
# ---------------------------------------------------------------------------


def test_configure_registry_auth_no_env_returns_zero(tmp_path, monkeypatch):
    from runner.scanners.container.registry_auth import configure_registry_auth

    monkeypatch.delenv("REGISTRY_AUTHS", raising=False)
    result = configure_registry_auth(config_dir=tmp_path)
    assert result == 0
    assert not (tmp_path / "config.json").exists()


def test_configure_registry_auth_writes_config_for_valid_input(tmp_path, monkeypatch):
    from runner.scanners.container.registry_auth import configure_registry_auth

    monkeypatch.setenv(
        "REGISTRY_AUTHS",
        json.dumps(
            [
                {
                    "registry": "ghcr.io",
                    "token": "abc123",
                    "username": "alice",
                }
            ]
        ),
    )
    result = configure_registry_auth(config_dir=tmp_path)
    assert result == 1
    cfg_path = tmp_path / "config.json"
    assert cfg_path.exists()
    data = json.loads(cfg_path.read_text())
    assert data == {
        "auths": {"ghcr.io": {"username": "alice", "password": "abc123"}}
    }
    if os.name == "posix":
        mode = stat.S_IMODE(cfg_path.stat().st_mode)
        assert mode == 0o600


def test_configure_registry_auth_defaults_username_to_token(tmp_path, monkeypatch):
    from runner.scanners.container.registry_auth import configure_registry_auth

    monkeypatch.setenv(
        "REGISTRY_AUTHS",
        json.dumps([{"registry": "registry.example.com", "token": "xyz"}]),
    )
    configure_registry_auth(config_dir=tmp_path)
    data = json.loads((tmp_path / "config.json").read_text())
    assert data["auths"]["registry.example.com"]["username"] == "_token"


def test_configure_registry_auth_invalid_json_returns_zero(tmp_path, monkeypatch):
    from runner.scanners.container.registry_auth import configure_registry_auth

    monkeypatch.setenv("REGISTRY_AUTHS", "not-json{")
    result = configure_registry_auth(config_dir=tmp_path)
    assert result == 0
    assert not (tmp_path / "config.json").exists()


def test_configure_registry_auth_non_list_returns_zero(tmp_path, monkeypatch):
    from runner.scanners.container.registry_auth import configure_registry_auth

    monkeypatch.setenv("REGISTRY_AUTHS", json.dumps({"registry": "x", "token": "y"}))
    result = configure_registry_auth(config_dir=tmp_path)
    assert result == 0


def test_configure_registry_auth_skips_entries_missing_fields(tmp_path, monkeypatch):
    from runner.scanners.container.registry_auth import configure_registry_auth

    monkeypatch.setenv(
        "REGISTRY_AUTHS",
        json.dumps(
            [
                {"registry": "ghcr.io"},  # missing token
                {"token": "abc"},  # missing registry
                {"registry": "valid.io", "token": "tok"},
            ]
        ),
    )
    result = configure_registry_auth(config_dir=tmp_path)
    assert result == 1
    data = json.loads((tmp_path / "config.json").read_text())
    assert list(data["auths"].keys()) == ["valid.io"]


def test_configure_registry_auth_pops_env(tmp_path, monkeypatch):
    from runner.scanners.container.registry_auth import configure_registry_auth

    monkeypatch.setenv(
        "REGISTRY_AUTHS",
        json.dumps([{"registry": "ghcr.io", "token": "abc"}]),
    )
    configure_registry_auth(config_dir=tmp_path)
    assert "REGISTRY_AUTHS" not in os.environ


# ---------------------------------------------------------------------------
# Task 3.2 — normalize.py
# ---------------------------------------------------------------------------


def _container_grype_match(
    *,
    pkg_name: str = "openssl",
    pkg_version: str = "1.1.1k",
    advisory_id: str = "GHSA-aaaa-bbbb-cccc",
    severity: str = "High",
    manifest_path: str = "/usr/lib/openssl",
    related: list[dict] | None = None,
    urls: list[str] | None = None,
) -> dict:
    return {
        "vulnerability": {
            "id": advisory_id,
            "severity": severity,
            "description": "Heap overflow in OpenSSL.",
            "cvss": [{"metrics": {"baseScore": 8.1}}],
            "fix": {"versions": ["1.1.1l"], "state": "fixed"},
            "versionConstraint": "< 1.1.1l",
            "publishedDate": "2021-08-24T00:00:00Z",
            "modifiedDate": "2021-09-01T00:00:00Z",
            "urls": urls if urls is not None else ["https://example.com/advisory"],
        },
        "relatedVulnerabilities": related or [],
        "artifact": {
            "name": pkg_name,
            "version": pkg_version,
            "type": "deb",
            "locations": [{"path": manifest_path}],
        },
    }


def test_container_normalize_file_emits_expected_shape(tmp_path):
    from runner.scanners.container.normalize import normalize_file

    grype_path = tmp_path / "findings.json"
    grype_path.write_text(json.dumps({"matches": [_container_grype_match()]}))

    findings = normalize_file(
        grype_path,
        org="acme",
        image_ref="gcr.io/acme/api:1.2.3",
        image_digest="sha256:abc123",
    )

    assert len(findings) == 1
    f = findings[0]
    assert f["organization"] == "acme"
    assert f["repository"] == "gcr.io/acme/api"
    assert f["source"] == "container"
    assert f["commitSha"] == "sha256:abc123"
    assert f["packageName"] == "openssl"
    assert f["packageVersion"] == "1.1.1k"
    assert f["manifestPath"] == "/usr/lib/openssl"
    assert f["ecosystem"] == "deb"
    assert f["advisoryId"] == "GHSA-aaaa-bbbb-cccc"
    assert f["ghsaId"] == "GHSA-aaaa-bbbb-cccc"
    assert f["cveId"] is None
    assert f["severity"] == "high"
    assert f["cvssScore"] == 8.1
    assert f["fixedVersion"] == "1.1.1l"
    assert f["fixState"] == "fixed"
    assert f["vulnerableVersionRange"] == "< 1.1.1l"
    assert f["publishedDate"] == "2021-08-24T00:00:00Z"
    assert f["lastModifiedDate"] == "2021-09-01T00:00:00Z"
    assert f["summary"] == "Heap overflow in OpenSSL."
    assert f["description"] == "Heap overflow in OpenSSL."
    assert f["references"] == [{"url": "https://example.com/advisory"}]
    assert f["scanner"] == "grype"
    assert f["stateCandidate"] == "open"
    assert f["imageName"] == "gcr.io/acme/api"
    assert f["imageTag"] == "1.2.3"
    assert f["imageDigest"] == "sha256:abc123"
    # Container advisory parity with SCA (C8): aliases + synthesized
    # manifestSnippet so the verifier prompt has the same fields the SCA
    # verifier consumes. The snippet must be multi-line so the prompt's
    # triple-backtick code fence renders with actual content.
    assert f["advisoryAliases"] == []
    assert f["manifestSnippet"]
    snippet_lines = f["manifestSnippet"].split("\n")
    assert len(snippet_lines) >= 2
    assert "package: openssl@1.1.1k" in snippet_lines
    assert "ecosystem: deb" in snippet_lines
    assert "manifest_path: /usr/lib/openssl" in snippet_lines


def test_container_normalize_file_aliases_from_related(tmp_path):
    """advisoryAliases must include related CVE/GHSA ids distinct from the primary."""
    from runner.scanners.container.normalize import normalize_file

    grype_path = tmp_path / "findings.json"
    grype_path.write_text(
        json.dumps(
            {
                "matches": [
                    _container_grype_match(
                        advisory_id="GHSA-aaaa-bbbb-cccc",
                        related=[
                            {"id": "CVE-2024-1111"},
                            {"id": "CVE-2024-2222"},
                            # duplicates and self-reference must be filtered out
                            {"id": "CVE-2024-1111"},
                            {"id": "GHSA-aaaa-bbbb-cccc"},
                        ],
                    )
                ]
            }
        )
    )
    f = normalize_file(grype_path, "acme", "alpine:3.18", "")[0]
    assert f["advisoryAliases"] == ["CVE-2024-1111", "CVE-2024-2222"]


def test_container_normalize_file_extracts_cve_from_related(tmp_path):
    from runner.scanners.container.normalize import normalize_file

    grype_path = tmp_path / "findings.json"
    grype_path.write_text(
        json.dumps(
            {
                "matches": [
                    _container_grype_match(
                        advisory_id="GHSA-1111",
                        related=[{"id": "CVE-2024-9999"}],
                    )
                ]
            }
        )
    )
    findings = normalize_file(grype_path, "acme", "alpine:3.18", "")
    f = findings[0]
    assert f["ghsaId"] == "GHSA-1111"
    assert f["cveId"] == "CVE-2024-9999"
    assert f["advisoryId"] == "GHSA-1111"


def test_container_normalize_file_handles_missing_optional_fields(tmp_path):
    from runner.scanners.container.normalize import normalize_file

    grype_path = tmp_path / "findings.json"
    grype_path.write_text(
        json.dumps(
            {
                "matches": [
                    {
                        "vulnerability": {"id": "CVE-2024-1234"},
                        "artifact": {"name": "foo", "version": "1.0", "type": "apk"},
                    }
                ]
            }
        )
    )
    findings = normalize_file(grype_path, "acme", "alpine:3.18", "")
    f = findings[0]
    assert f["severity"] == "unknown"
    assert f["cvssScore"] is None
    assert f["fixedVersion"] is None
    assert f["fixState"] == "unknown"
    assert f["references"] == []
    assert f["manifestPath"] == ""
    assert f["cveId"] == "CVE-2024-1234"
    assert f["ghsaId"] is None
    assert f["advisoryId"] == "CVE-2024-1234"


def test_container_normalize_file_truncates_summary(tmp_path):
    from runner.scanners.container.normalize import normalize_file

    long_desc = "x" * 500
    grype_path = tmp_path / "findings.json"
    grype_path.write_text(
        json.dumps(
            {
                "matches": [
                    {
                        "vulnerability": {"id": "CVE-1", "description": long_desc},
                        "artifact": {"name": "p", "version": "0", "type": "deb"},
                    }
                ]
            }
        )
    )
    f = normalize_file(grype_path, "acme", "img", "")[0]
    assert len(f["summary"]) == 200
    assert f["description"] == long_desc


def test_container_normalize_file_image_ref_without_tag(tmp_path):
    from runner.scanners.container.normalize import normalize_file

    grype_path = tmp_path / "findings.json"
    grype_path.write_text(json.dumps({"matches": [_container_grype_match()]}))
    f = normalize_file(grype_path, "acme", "alpine", "")[0]
    assert f["imageName"] == "alpine"
    assert f["imageTag"] == "latest"


def test_container_normalize_grype_output_writes_jsonl(tmp_path):
    from runner.scanners.container.normalize import normalize_grype_output

    image_dir = tmp_path / "alpine__3.18"
    image_dir.mkdir()
    (image_dir / "findings.json").write_text(
        json.dumps({"matches": [_container_grype_match()]})
    )
    (image_dir / "sbom.cdx.json").write_text(
        json.dumps({"metadata": {"component": {"name": "alpine:3.18"}}})
    )
    (image_dir / "digest.txt").write_text("sha256:deadbeef\n")

    total, errors = normalize_grype_output("acme", tmp_path)
    assert total == 1
    assert errors == 0

    out_file = tmp_path / "findings.jsonl"
    assert out_file.exists()
    lines = [json.loads(line) for line in out_file.read_text().splitlines()]
    assert len(lines) == 1
    assert lines[0]["organization"] == "acme"
    assert lines[0]["imageName"] == "alpine"
    assert lines[0]["imageTag"] == "3.18"
    assert lines[0]["imageDigest"] == "sha256:deadbeef"
    assert lines[0]["commitSha"] == "sha256:deadbeef"


def test_container_normalize_grype_output_skips_when_sbom_missing(tmp_path):
    from runner.scanners.container.normalize import normalize_grype_output

    image_dir = tmp_path / "x"
    image_dir.mkdir()
    (image_dir / "findings.json").write_text(
        json.dumps({"matches": [_container_grype_match()]})
    )

    total, errors = normalize_grype_output("acme", tmp_path)
    assert total == 0
    assert errors == 0


def test_container_normalize_grype_output_handles_empty(tmp_path):
    from runner.scanners.container.normalize import normalize_grype_output

    total, errors = normalize_grype_output("acme", tmp_path)
    assert total == 0
    assert errors == 0
    assert (tmp_path / "findings.jsonl").exists()


def test_container_attach_advisory_details_enriches_by_primary_id(tmp_path, monkeypatch):
    """attach_advisory_details populates advisoryDetail keyed on advisoryId."""
    from runner.scanners.container import normalize as container_normalize
    from runner.scanners.dependencies.advisory_enrichment import AdvisoryDetail

    captured: dict = {}

    def fake_fetch(advisory_ids, *, cache_dir=None, nvd_api_key=None):
        captured["ids"] = list(advisory_ids)
        return {
            "CVE-2024-1234": AdvisoryDetail(
                advisory_id="CVE-2024-1234",
                summary="long-form summary",
                description="long-form description from NVD",
                references=("https://nvd.nist.gov/vuln/detail/CVE-2024-1234",),
                cwes=("CWE-79",),
                vulnerable_version_range="< 1.2.3",
            ),
        }

    monkeypatch.setattr(
        container_normalize.advisory_enrichment,
        "fetch_advisory_details",
        fake_fetch,
    )

    findings = [
        {"advisoryId": "CVE-2024-1234", "advisoryAliases": ["GHSA-zzzz-yyyy-xxxx"]},
        {"advisoryId": "", "advisoryAliases": []},
    ]
    container_normalize.attach_advisory_details(findings)

    assert "CVE-2024-1234" in captured["ids"]
    assert findings[0]["advisoryDetail"]["summary"] == "long-form summary"
    assert findings[0]["advisoryDetail"]["cwes"] == ["CWE-79"]
    # Finding without an advisory id gets a None placeholder — matches SCA shape.
    assert findings[1]["advisoryDetail"] is None


def test_container_attach_advisory_details_falls_back_to_alias(tmp_path, monkeypatch):
    """When the primary id is unknown to enrichment, fall back to an alias hit."""
    from runner.scanners.container import normalize as container_normalize
    from runner.scanners.dependencies.advisory_enrichment import AdvisoryDetail

    def fake_fetch(advisory_ids, *, cache_dir=None, nvd_api_key=None):
        return {
            "CVE-2024-9999": AdvisoryDetail(
                advisory_id="CVE-2024-9999",
                summary="aliased advisory",
                description="",
            ),
        }

    monkeypatch.setattr(
        container_normalize.advisory_enrichment,
        "fetch_advisory_details",
        fake_fetch,
    )

    findings = [
        {"advisoryId": "GHSA-1111-2222-3333", "advisoryAliases": ["CVE-2024-9999"]},
    ]
    container_normalize.attach_advisory_details(findings)
    assert findings[0]["advisoryDetail"]["summary"] == "aliased advisory"


def test_container_normalize_grype_output_invokes_enrichment(tmp_path, monkeypatch):
    """End-to-end: normalize_grype_output should attach advisoryDetail when not disabled."""
    from runner.scanners.container import normalize as container_normalize
    from runner.scanners.dependencies.advisory_enrichment import AdvisoryDetail

    monkeypatch.delenv("AEGIS_DISABLE_EAGER_ENRICHMENT", raising=False)

    def fake_fetch(advisory_ids, *, cache_dir=None, nvd_api_key=None):
        return {
            "GHSA-aaaa-bbbb-cccc": AdvisoryDetail(
                advisory_id="GHSA-aaaa-bbbb-cccc",
                summary="nvd summary",
                description="long description",
                cwes=("CWE-122",),
            ),
        }

    monkeypatch.setattr(
        container_normalize.advisory_enrichment,
        "fetch_advisory_details",
        fake_fetch,
    )

    image_dir = tmp_path / "alpine__3.18"
    image_dir.mkdir()
    (image_dir / "findings.json").write_text(
        json.dumps({"matches": [_container_grype_match()]})
    )
    (image_dir / "sbom.cdx.json").write_text(
        json.dumps({"metadata": {"component": {"name": "alpine:3.18"}}})
    )

    total, errors = container_normalize.normalize_grype_output("acme", tmp_path)
    assert total == 1 and errors == 0

    line = (tmp_path / "findings.jsonl").read_text().splitlines()[0]
    finding = json.loads(line)
    assert finding["advisoryDetail"]["summary"] == "nvd summary"
    assert finding["advisoryDetail"]["cwes"] == ["CWE-122"]


def test_container_normalize_grype_output_skips_enrichment_when_disabled(
    tmp_path, monkeypatch
):
    """AEGIS_DISABLE_EAGER_ENRICHMENT=1 must skip the NVD/OSV fetch entirely."""
    from runner.scanners.container import normalize as container_normalize

    monkeypatch.setenv("AEGIS_DISABLE_EAGER_ENRICHMENT", "1")

    called: list = []

    def fake_fetch(advisory_ids, *, cache_dir=None, nvd_api_key=None):
        called.append(advisory_ids)
        return {}

    monkeypatch.setattr(
        container_normalize.advisory_enrichment,
        "fetch_advisory_details",
        fake_fetch,
    )

    image_dir = tmp_path / "alpine__3.18"
    image_dir.mkdir()
    (image_dir / "findings.json").write_text(
        json.dumps({"matches": [_container_grype_match()]})
    )
    (image_dir / "sbom.cdx.json").write_text(
        json.dumps({"metadata": {"component": {"name": "alpine:3.18"}}})
    )

    container_normalize.normalize_grype_output("acme", tmp_path)
    assert called == []


def test_container_normalize_output_uses_compact_json(tmp_path):
    """Confirms separators=(',', ':') — no whitespace between fields."""
    from runner.scanners.container.normalize import normalize_grype_output

    image_dir = tmp_path / "x"
    image_dir.mkdir()
    (image_dir / "findings.json").write_text(
        json.dumps({"matches": [_container_grype_match()]})
    )
    (image_dir / "sbom.cdx.json").write_text(
        json.dumps({"metadata": {"component": {"name": "x"}}})
    )
    normalize_grype_output("acme", tmp_path)
    line = (tmp_path / "findings.jsonl").read_text().splitlines()[0]
    # Compact form has no whitespace between key and value (e.g. "a":"b" not "a": "b")
    assert '": ' not in line
    assert '","' in line


# ---------------------------------------------------------------------------
# Task 3.3 — ContainerScanner orchestrator
# ---------------------------------------------------------------------------


def test_container_scanner_has_correct_type():
    from runner.scanners.container.scanner import ContainerScanner

    assert ContainerScanner.SCANNER_TYPE == "container_scanning"


def test_container_scanner_implements_base_protocol():
    from runner.scanners.base import BaseScanner
    from runner.scanners.container.scanner import ContainerScanner

    assert isinstance(ContainerScanner(), BaseScanner)


def test_run_scan_empty_images_returns_clean(tmp_path):
    from runner.scanners.base import ExecutionResult
    from runner.scanners.container.scanner import ContainerScanner

    scanner = ContainerScanner()
    job = {
        "jobId": "test-c-empty",
        "envVars": {"DOCKER_IMAGES": ""},
    }
    job_dir = tmp_path / "test-c-empty"
    result = scanner.run_scan(job, job_dir=job_dir)
    assert isinstance(result, ExecutionResult)
    assert result.exit_code == 0
    manifest = (job_dir / "_manifest.jsonl").read_text()
    assert '"file": "_done"' in manifest


def test_run_scan_missing_docker_args_does_not_crash(tmp_path):
    from runner.scanners.container.scanner import ContainerScanner

    scanner = ContainerScanner()
    result = scanner.run_scan({"jobId": "bare-c"}, job_dir=tmp_path / "bare-c")
    assert result.exit_code == 0


def test_run_scan_rejects_invalid_image_ref(tmp_path):
    """Invalid refs are dropped; if nothing is left, exit 0 with _done marker."""
    from runner.scanners.container.scanner import ContainerScanner

    scanner = ContainerScanner()
    job = {
        "jobId": "test-bad",
        "envVars": {"DOCKER_IMAGES": "alpine;rm -rf /,-evil"},
    }
    job_dir = tmp_path / "test-bad"
    result = scanner.run_scan(job, job_dir=job_dir)
    assert result.exit_code == 0
    assert any("Invalid image reference" in m for m in result.log_tail)
    manifest = (job_dir / "_manifest.jsonl").read_text()
    assert '"file": "_done"' in manifest


def test_run_scan_pre_cancel_returns_137(tmp_path):
    from runner.scanners._subprocess import CANCELLED_EXIT_CODE
    from runner.scanners.container.scanner import ContainerScanner

    scanner = ContainerScanner()
    cancel = threading.Event()
    cancel.set()
    job = {
        "jobId": "test-cancel",
        "envVars": {"DOCKER_IMAGES": "alpine:3.18"},
    }
    result = scanner.run_scan(
        job, job_dir=tmp_path / "test-cancel", cancel_event=cancel
    )
    assert result.exit_code == CANCELLED_EXIT_CODE


def test_run_scan_rejects_unsupported_scan_mode(tmp_path):
    from runner.scanners.container.scanner import ContainerScanner

    scanner = ContainerScanner()
    job = {
        "jobId": "test-mode",
        "envVars": {
                "DOCKER_IMAGES": "alpine:3.18",
                "SCAN_MODE": "not_a_real_mode",
            },
    }
    job_dir = tmp_path / "test-mode"
    result = scanner.run_scan(job, job_dir=job_dir)
    assert result.exit_code == 2
    assert any("SCAN_MODE" in m for m in result.log_tail)
    manifest = (job_dir / "_manifest.jsonl").read_text()
    assert '"file": "_done"' in manifest


@pytest.mark.parametrize(
    "ref,expected",
    [
        ("alpine:3.18", True),
        ("gcr.io/proj/img:tag", True),
        ("gcr.io/proj/img@sha256:abc123", True),
        ("alpine;rm -rf /", False),
        ("-evil", False),
        ("", False),
        ("alpine $(curl evil)", False),
        ("alpine|whoami", False),
        ("a", True),
    ],
)
def test_validate_image_ref(ref, expected):
    from runner.scanners.container.scanner import _validate_image_ref

    assert _validate_image_ref(ref) is expected


@pytest.mark.parametrize(
    "ref,expected",
    [
        ("alpine:3.18", "alpine_3.18"),
        ("gcr.io/proj/img:tag", "gcr.io_proj_img_tag"),
        ("name", "name"),
    ],
)
def test_sanitize_name(ref, expected):
    from runner.scanners.container.scanner import _sanitize_name

    assert _sanitize_name(ref) == expected


def test_run_scan_honours_concurrency_env(tmp_path, monkeypatch):
    from runner.scanners.container import scanner as scanner_mod
    from runner.scanners.container.scanner import ContainerScanner

    captured: dict = {}

    class _StubPool:
        def __init__(self, max_workers):
            captured["max_workers"] = max_workers

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def map(self, fn, items):
            return [fn(i) for i in items]

    monkeypatch.setattr(
        scanner_mod.concurrent.futures, "ThreadPoolExecutor", _StubPool
    )
    monkeypatch.setattr(
        ContainerScanner, "_ensure_grype_db", lambda self, c: None
    )
    monkeypatch.setattr(
        ContainerScanner, "_scan_image", lambda self, *a, **kw: None
    )

    scanner = ContainerScanner()
    job = {
        "jobId": "test-conc",
        "envVars": {
                "DOCKER_IMAGES": "alpine:3.18,debian:12",
                "CONCURRENCY": "5",
            },
    }
    scanner.run_scan(job, job_dir=tmp_path / "test-conc")
    assert captured["max_workers"] == 5


def test_run_scan_aggregates_findings(tmp_path, monkeypatch):
    """Per-image findings.json files should be aggregated into findings.jsonl."""
    from runner.scanners.container import scanner as scanner_mod
    from runner.scanners.container.scanner import ContainerScanner

    def fake_scan_image(self, image_ref, out_dir, **kwargs):
        safe_name = scanner_mod._sanitize_name(image_ref)
        image_out = out_dir / safe_name
        image_out.mkdir(parents=True, exist_ok=True)
        (image_out / "sbom.cdx.json").write_text(
            json.dumps({"metadata": {"component": {"name": image_ref}}})
        )
        (image_out / "findings.json").write_text(
            json.dumps(
                {
                    "matches": [
                        {
                            "vulnerability": {"id": f"CVE-{safe_name}"},
                            "artifact": {
                                "name": "pkg",
                                "version": "1.0",
                                "type": "deb",
                            },
                        }
                    ]
                }
            )
        )
        return image_out / "findings.json"

    monkeypatch.setattr(
        ContainerScanner, "_ensure_grype_db", lambda self, c: None
    )
    monkeypatch.setattr(ContainerScanner, "_scan_image", fake_scan_image)

    scanner = ContainerScanner()
    job = {
        "jobId": "test-agg",
        "envVars": {
                "DOCKER_IMAGES": "alpine:3.18\ndebian:12",
                "ORG_LABEL": "acme",
            },
    }
    job_dir = tmp_path / "test-agg"
    result = scanner.run_scan(job, job_dir=job_dir)
    assert result.exit_code == 0
    aggregated = (job_dir / "findings.jsonl").read_text().splitlines()
    advisory_ids = sorted(json.loads(line)["advisoryId"] for line in aggregated)
    assert advisory_ids == ["CVE-alpine_3.18", "CVE-debian_12"]
    # Per-image rows carry the raw image name, not the sanitised dir name.
    image_names = sorted(json.loads(line)["imageName"] for line in aggregated)
    assert image_names == ["alpine", "debian"]


def test_run_scan_tolerates_per_image_failure(tmp_path, monkeypatch):
    from runner.scanners.container import scanner as scanner_mod
    from runner.scanners.container.scanner import ContainerScanner

    def fake_scan_image(self, image_ref, out_dir, **kwargs):
        raise RuntimeError(f"simulated failure for {image_ref}")

    monkeypatch.setattr(
        ContainerScanner, "_ensure_grype_db", lambda self, c: None
    )
    monkeypatch.setattr(ContainerScanner, "_scan_image", fake_scan_image)

    scanner = ContainerScanner()
    job = {
        "jobId": "test-fail",
        "envVars": {"DOCKER_IMAGES": "alpine:3.18"},
    }
    job_dir = tmp_path / "test-fail"
    result = scanner.run_scan(job, job_dir=job_dir)
    assert result.exit_code == 0
    assert any("simulated failure" in line for line in result.log_tail)


def test_run_scan_invokes_registry_auth(tmp_path, monkeypatch):
    """Job-supplied REGISTRY_AUTHS must be promoted to env so configure_registry_auth picks it up."""
    from runner.scanners.container import scanner as scanner_mod
    from runner.scanners.container.scanner import ContainerScanner

    monkeypatch.delenv("REGISTRY_AUTHS", raising=False)
    seen: dict = {}

    def fake_configure(config_dir=None):
        seen["env_val"] = os.environ.pop("REGISTRY_AUTHS", None)
        return 1

    monkeypatch.setattr(
        scanner_mod.registry_auth, "configure_registry_auth", fake_configure
    )
    monkeypatch.setattr(
        ContainerScanner, "_ensure_grype_db", lambda self, c: None
    )
    monkeypatch.setattr(
        ContainerScanner, "_scan_image", lambda self, *a, **kw: None
    )

    scanner = ContainerScanner()
    job = {
        "jobId": "test-auth",
        "envVars": {
                "DOCKER_IMAGES": "alpine:3.18",
                "REGISTRY_AUTHS": '[{"registry":"ghcr.io","token":"x"}]',
            },
    }
    scanner.run_scan(job, job_dir=tmp_path / "test-auth")
    assert seen["env_val"] == '[{"registry":"ghcr.io","token":"x"}]'


def test_read_sbom_sha256_extracts_digest(tmp_path):
    from runner.scanners.container.scanner import _read_sbom_sha256

    sbom = tmp_path / "sbom.json"
    sbom.write_text(
        json.dumps(
            {
                "metadata": {
                    "component": {
                        "hashes": [
                            {"alg": "MD5", "content": "ignore"},
                            {"alg": "SHA-256", "content": "deadbeef"},
                        ]
                    }
                }
            }
        )
    )
    assert _read_sbom_sha256(sbom) == "deadbeef"


def test_read_sbom_sha256_returns_none_when_missing(tmp_path):
    from runner.scanners.container.scanner import _read_sbom_sha256

    sbom = tmp_path / "sbom.json"
    sbom.write_text(json.dumps({"metadata": {"component": {}}}))
    assert _read_sbom_sha256(sbom) is None


def test_run_scan_emits_progress(tmp_path):
    """on_progress should be called with the expected dict shape, terminating
    in stage='done'."""
    from runner.scanners.container.scanner import ContainerScanner

    captures: list[dict] = []

    def on_progress(log_tail, progress):
        captures.append(dict(progress))

    scanner = ContainerScanner()
    job = {"jobId": "p1", "envVars": {"DOCKER_IMAGES": ""}}
    scanner.run_scan(job, job_dir=tmp_path / "p1", on_progress=on_progress)

    assert captures, "on_progress was never called"
    assert any(c.get("stage") == "done" for c in captures)
    assert all("scannedRepos" in c for c in captures)
    assert all("finishedRepos" in c for c in captures)
    assert all("expectedRepos" in c for c in captures)


def test_run_scan_emits_progress_per_image(tmp_path, monkeypatch):
    """Each image must produce monotonic scanning/finished counters and the
    run must terminate in stage='done'. Container jobs reuse the *Repos
    counter names from the shared backend schema."""
    from runner.scanners.container import scanner as scanner_mod
    from runner.scanners.container.scanner import ContainerScanner

    monkeypatch.setattr(ContainerScanner, "_ensure_grype_db", lambda self, c: None)
    monkeypatch.setattr(
        scanner_mod.registry_auth, "configure_registry_auth", lambda: 0
    )
    monkeypatch.setattr(
        ContainerScanner, "_scan_image", lambda self, ref, out, **kw: None
    )

    captures: list[dict] = []
    scanner = ContainerScanner()
    job = {
        "jobId": "p2",
        "envVars": {
                "DOCKER_IMAGES": "alpine:3.20,debian:12",
                "CONCURRENCY": "1",
            },
    }
    scanner.run_scan(
        job,
        job_dir=tmp_path / "p2",
        on_progress=lambda lt, p: captures.append(dict(p)),
    )

    assert all(c["expectedRepos"] == 2 for c in captures)
    assert [c["scannedRepos"] for c in captures] == sorted(
        c["scannedRepos"] for c in captures
    )
    assert [c["finishedRepos"] for c in captures] == sorted(
        c["finishedRepos"] for c in captures
    )
    assert captures[-1]["stage"] == "done"
    assert captures[-1]["finishedRepos"] == 2
    assert any(c.get("stage") == "scanning" for c in captures)
    assert any(c.get("stage") == "normalizing" for c in captures)


def test_run_scan_emits_progress_done_on_unsupported_mode(tmp_path):
    """The unsupported-mode early exit must still emit stage='done'."""
    from runner.scanners.container.scanner import ContainerScanner

    captures: list[dict] = []
    scanner = ContainerScanner()
    job = {
        "jobId": "p3",
        "envVars": {
                "DOCKER_IMAGES": "alpine:3.20",
                "SCAN_MODE": "not_a_real_mode",
            },
    }
    scanner.run_scan(
        job,
        job_dir=tmp_path / "p3",
        on_progress=lambda lt, p: captures.append(dict(p)),
    )
    assert captures and captures[-1]["stage"] == "done"


def test_run_scan_emits_progress_done_on_pre_cancel(tmp_path):
    import threading as _threading

    from runner.scanners.container.scanner import ContainerScanner

    captures: list[dict] = []
    cancel = _threading.Event()
    cancel.set()
    scanner = ContainerScanner()
    job = {
        "jobId": "p4",
        "envVars": {"DOCKER_IMAGES": "alpine:3.20"},
    }
    scanner.run_scan(
        job,
        job_dir=tmp_path / "p4",
        on_progress=lambda lt, p: captures.append(dict(p)),
        cancel_event=cancel,
    )
    assert captures and captures[-1]["stage"] == "done"


def test_run_scan_progress_callback_exception_does_not_abort(tmp_path):
    from runner.scanners.container.scanner import ContainerScanner

    def bad(log_tail, progress):
        raise RuntimeError("boom")

    scanner = ContainerScanner()
    job = {"jobId": "p5", "envVars": {"DOCKER_IMAGES": ""}}
    result = scanner.run_scan(job, job_dir=tmp_path / "p5", on_progress=bad)
    assert result.exit_code == 0


# ---------------------------------------------------------------------------
# Gap 1 — PREVIOUS_DIGESTS skip-unchanged
# ---------------------------------------------------------------------------


def test_parse_previous_digests_valid_object():
    from runner.scanners.container.digest_compare import parse_previous_digests

    raw = json.dumps({"alpine:3.18": "sha256:aaa", "debian:12": "sha256:bbb"})
    out = parse_previous_digests(raw)
    assert out == {"alpine:3.18": "sha256:aaa", "debian:12": "sha256:bbb"}


def test_parse_previous_digests_empty_or_missing():
    from runner.scanners.container.digest_compare import parse_previous_digests

    assert parse_previous_digests("") == {}
    assert parse_previous_digests(None) == {}


def test_parse_previous_digests_malformed_json_returns_empty():
    from runner.scanners.container.digest_compare import parse_previous_digests

    assert parse_previous_digests("{not-json") == {}
    assert parse_previous_digests("[]") == {}
    assert parse_previous_digests("\"string\"") == {}


def test_lookup_previous_digest_matches_full_ref():
    from runner.scanners.container.digest_compare import lookup_previous_digest

    prev = {"gcr.io/proj/img:1.0": "sha256:aaa"}
    assert lookup_previous_digest("gcr.io/proj/img:1.0", prev) == "sha256:aaa"


def test_lookup_previous_digest_matches_name_without_tag():
    from runner.scanners.container.digest_compare import lookup_previous_digest

    prev = {"alpine": "sha256:bbb"}
    assert lookup_previous_digest("alpine:3.18", prev) == "sha256:bbb"


def test_lookup_previous_digest_returns_none_when_absent():
    from runner.scanners.container.digest_compare import lookup_previous_digest

    assert lookup_previous_digest("alpine:3.18", {}) is None
    assert lookup_previous_digest("alpine:3.18", {"debian:12": "x"}) is None


def test_digests_match_normalizes_prefix():
    from runner.scanners.container.digest_compare import digests_match

    assert digests_match("sha256:DEADBEEF", "deadbeef") is True
    assert digests_match("sha256:aaa", "sha256:bbb") is False
    assert digests_match(None, "sha256:aaa") is False
    assert digests_match("", "sha256:aaa") is False


def test_previous_digests_skips_unchanged_image(tmp_path, monkeypatch):
    """Given matching previous + registry HEAD digests, syft+grype are skipped."""
    from runner.scanners.container import scanner as scanner_mod
    from runner.scanners.container.scanner import ContainerScanner

    monkeypatch.setattr(ContainerScanner, "_ensure_grype_db", lambda self, c: None)
    monkeypatch.setattr(
        scanner_mod.registry_auth, "configure_registry_auth", lambda: 0
    )
    # Registry HEAD reports the same digest the backend remembered.
    monkeypatch.setattr(
        scanner_mod.registry_digest,
        "fetch_registry_digest",
        lambda image_ref, **kw: "sha256:cafef00d",
    )

    syft_calls: list = []
    grype_calls: list = []
    monkeypatch.setattr(
        ContainerScanner,
        "_run_syft",
        lambda self, *a, **kw: syft_calls.append(a) or True,
    )
    monkeypatch.setattr(
        ContainerScanner,
        "_run_grype",
        lambda self, *a, **kw: grype_calls.append(a) or True,
    )

    scanner = ContainerScanner()
    job = {
        "jobId": "skip-test",
        "envVars": {
                "DOCKER_IMAGES": "gcr.io/proj/img:1.0",
                "PREVIOUS_DIGESTS": json.dumps(
                    {"gcr.io/proj/img:1.0": "sha256:cafef00d"}
                ),
            },
    }
    job_dir = tmp_path / "skip-test"
    result = scanner.run_scan(job, job_dir=job_dir)
    assert result.exit_code == 0
    assert syft_calls == []
    assert grype_calls == []
    digest_file = job_dir / "gcr.io_proj_img_1.0" / "digest.txt"
    assert digest_file.exists()
    assert "sha256:cafef00d" in digest_file.read_text()


def test_previous_digests_skipped_image_still_emits_progress(
    tmp_path, monkeypatch
):
    """Finished counter must increment even for skipped images."""
    from runner.scanners.container import scanner as scanner_mod
    from runner.scanners.container.scanner import ContainerScanner

    monkeypatch.setattr(ContainerScanner, "_ensure_grype_db", lambda self, c: None)
    monkeypatch.setattr(
        scanner_mod.registry_auth, "configure_registry_auth", lambda: 0
    )
    monkeypatch.setattr(
        scanner_mod.registry_digest,
        "fetch_registry_digest",
        lambda image_ref, **kw: "sha256:aaa",
    )

    captures: list[dict] = []
    scanner = ContainerScanner()
    job = {
        "jobId": "skip-progress",
        "envVars": {
                "DOCKER_IMAGES": "gcr.io/proj/a:1.0,gcr.io/proj/b:1.0",
                "PREVIOUS_DIGESTS": json.dumps(
                    {
                        "gcr.io/proj/a:1.0": "sha256:aaa",
                        "gcr.io/proj/b:1.0": "sha256:aaa",
                    }
                ),
                "CONCURRENCY": "1",
            },
    }
    scanner.run_scan(
        job,
        job_dir=tmp_path / "skip-progress",
        on_progress=lambda lt, p: captures.append(dict(p)),
    )
    assert captures[-1]["stage"] == "done"
    assert captures[-1]["finishedRepos"] == 2


def test_previous_digests_skipped_image_writes_manifest_entry(
    tmp_path, monkeypatch
):
    """The skipped image's digest.txt must be recorded in _manifest.jsonl."""
    from runner.scanners.container import scanner as scanner_mod
    from runner.scanners.container.scanner import ContainerScanner

    monkeypatch.setattr(ContainerScanner, "_ensure_grype_db", lambda self, c: None)
    monkeypatch.setattr(
        scanner_mod.registry_auth, "configure_registry_auth", lambda: 0
    )
    monkeypatch.setattr(
        scanner_mod.registry_digest,
        "fetch_registry_digest",
        lambda image_ref, **kw: "sha256:abc",
    )

    scanner = ContainerScanner()
    job = {
        "jobId": "skip-manifest",
        "envVars": {
                "DOCKER_IMAGES": "gcr.io/proj/img:1.0",
                "PREVIOUS_DIGESTS": json.dumps(
                    {"gcr.io/proj/img:1.0": "sha256:abc"}
                ),
            },
    }
    job_dir = tmp_path / "skip-manifest"
    scanner.run_scan(job, job_dir=job_dir)
    manifest_text = (job_dir / "_manifest.jsonl").read_text()
    assert "digest.txt" in manifest_text


def test_previous_digests_invalid_json_warns_and_proceeds(tmp_path, monkeypatch):
    """Malformed PREVIOUS_DIGESTS env must not crash the scanner."""
    from runner.scanners.container import scanner as scanner_mod
    from runner.scanners.container.scanner import ContainerScanner

    monkeypatch.setattr(ContainerScanner, "_ensure_grype_db", lambda self, c: None)
    monkeypatch.setattr(
        scanner_mod.registry_auth, "configure_registry_auth", lambda: 0
    )
    monkeypatch.setattr(
        ContainerScanner, "_scan_image", lambda self, *a, **kw: None
    )

    scanner = ContainerScanner()
    job = {
        "jobId": "bad-prev",
        "envVars": {
                "DOCKER_IMAGES": "alpine:3.18",
                "PREVIOUS_DIGESTS": "{not-json",
            },
    }
    result = scanner.run_scan(job, job_dir=tmp_path / "bad-prev")
    assert result.exit_code == 0
    assert any("PREVIOUS_DIGESTS" in line for line in result.log_tail)


def test_previous_digests_mismatch_still_invokes_syft(tmp_path, monkeypatch):
    """When the registry digest differs from the previous digest, fall through."""
    from runner.scanners.container import scanner as scanner_mod
    from runner.scanners.container.scanner import ContainerScanner

    monkeypatch.setattr(ContainerScanner, "_ensure_grype_db", lambda self, c: None)
    monkeypatch.setattr(
        scanner_mod.registry_auth, "configure_registry_auth", lambda: 0
    )
    monkeypatch.setattr(
        scanner_mod.registry_digest,
        "fetch_registry_digest",
        lambda image_ref, **kw: "sha256:NEW",
    )

    called: list = []

    def fake_syft(self, image_ref, scan_platform, output, cancel_event, **_):
        called.append(image_ref)
        output.write_text(
            json.dumps({"metadata": {"component": {"name": image_ref}}})
        )
        return True

    monkeypatch.setattr(ContainerScanner, "_run_syft", fake_syft)
    monkeypatch.setattr(
        ContainerScanner, "_run_grype", lambda self, *a, **kw: True
    )

    scanner = ContainerScanner()
    job = {
        "jobId": "mismatch",
        "envVars": {
                "DOCKER_IMAGES": "gcr.io/proj/img:1.0",
                "PREVIOUS_DIGESTS": json.dumps(
                    {"gcr.io/proj/img:1.0": "sha256:OLD"}
                ),
            },
    }
    scanner.run_scan(job, job_dir=tmp_path / "mismatch")
    assert called == ["gcr.io/proj/img:1.0"]


# ---------------------------------------------------------------------------
# Gap 2 — Registry HEAD digest fallback (SSRF-guarded)
# ---------------------------------------------------------------------------


def test_fetch_registry_digest_uses_sbom_hash_when_present(
    tmp_path, monkeypatch
):
    """When SBOM has a SHA-256 hash, registry HEAD must NOT be called."""
    from runner.scanners.container import scanner as scanner_mod
    from runner.scanners.container.scanner import ContainerScanner

    monkeypatch.setattr(ContainerScanner, "_ensure_grype_db", lambda self, c: None)
    monkeypatch.setattr(
        scanner_mod.registry_auth, "configure_registry_auth", lambda: 0
    )

    head_calls: list = []

    def fake_head(image_ref, **kw):
        head_calls.append(image_ref)
        return "sha256:fallback"

    monkeypatch.setattr(
        scanner_mod.registry_digest, "fetch_registry_digest", fake_head
    )

    def fake_syft(self, image_ref, scan_platform, output, cancel_event, **_):
        output.write_text(
            json.dumps(
                {
                    "metadata": {
                        "component": {
                            "name": image_ref,
                            "hashes": [
                                {"alg": "SHA-256", "content": "fromsbom"}
                            ],
                        }
                    }
                }
            )
        )
        return True

    monkeypatch.setattr(ContainerScanner, "_run_syft", fake_syft)
    monkeypatch.setattr(
        ContainerScanner, "_run_grype", lambda self, *a, **kw: True
    )

    scanner = ContainerScanner()
    job = {
        "jobId": "sbom-hash",
        "envVars": {"DOCKER_IMAGES": "gcr.io/proj/img:1.0"},
    }
    job_dir = tmp_path / "sbom-hash"
    scanner.run_scan(job, job_dir=job_dir)
    digest_text = (job_dir / "gcr.io_proj_img_1.0" / "digest.txt").read_text()
    assert digest_text == "sha256:fromsbom"
    # No PREVIOUS_DIGESTS lookup and SBOM had a hash → HEAD must not be called.
    assert head_calls == []


def test_fetch_registry_digest_falls_back_to_registry_head(tmp_path, monkeypatch):
    """When the SBOM lacks SHA-256, the registry HEAD digest is used."""
    from runner.scanners.container import scanner as scanner_mod
    from runner.scanners.container.scanner import ContainerScanner

    monkeypatch.setattr(ContainerScanner, "_ensure_grype_db", lambda self, c: None)
    monkeypatch.setattr(
        scanner_mod.registry_auth, "configure_registry_auth", lambda: 0
    )
    monkeypatch.setattr(
        scanner_mod.registry_digest,
        "fetch_registry_digest",
        lambda image_ref, **kw: "sha256:fromregistry",
    )

    def fake_syft(self, image_ref, scan_platform, output, cancel_event, **_):
        output.write_text(
            json.dumps({"metadata": {"component": {"name": image_ref}}})
        )
        return True

    monkeypatch.setattr(ContainerScanner, "_run_syft", fake_syft)
    monkeypatch.setattr(
        ContainerScanner, "_run_grype", lambda self, *a, **kw: True
    )

    scanner = ContainerScanner()
    job = {
        "jobId": "head-fallback",
        "envVars": {"DOCKER_IMAGES": "gcr.io/proj/img:1.0"},
    }
    job_dir = tmp_path / "head-fallback"
    scanner.run_scan(job, job_dir=job_dir)
    digest_text = (job_dir / "gcr.io_proj_img_1.0" / "digest.txt").read_text()
    assert digest_text == "sha256:fromregistry"


def test_registry_digest_returns_none_when_curl_fails(tmp_path, monkeypatch):
    from runner.scanners.container import registry_digest as rd

    # Resolution succeeds with a public IP so the SSRF gate passes.
    monkeypatch.setattr(rd, "_resolve_host", lambda h: ["93.184.216.34"])
    monkeypatch.setattr(
        rd, "_read_docker_password", lambda *a, **kw: None
    )
    # curl fails (non-zero rc).
    monkeypatch.setattr(rd, "run_tool", lambda args, **kw: (1, "", "boom"))

    result = rd.fetch_registry_digest("gcr.io/proj/img:1.0")
    assert result is None


def test_registry_digest_rejects_localhost(monkeypatch):
    from runner.scanners.container import registry_digest as rd

    monkeypatch.setattr(
        rd,
        "run_tool",
        lambda args, **kw: pytest.fail("run_tool must not be called"),
    )
    assert rd.fetch_registry_digest("localhost/x/y:1") is None
    assert rd.fetch_registry_digest("metadata.google.internal/x/y:1") is None
    assert rd.fetch_registry_digest("169.254.169.254/x/y:1") is None


def test_registry_digest_rejects_rfc1918(monkeypatch):
    from runner.scanners.container import registry_digest as rd

    monkeypatch.setattr(rd, "_resolve_host", lambda h: ["10.0.0.5"])
    monkeypatch.setattr(
        rd,
        "run_tool",
        lambda args, **kw: pytest.fail("run_tool must not be called"),
    )
    assert rd.fetch_registry_digest("internal-registry.example/x/y:1") is None


def test_registry_digest_rejects_192_168(monkeypatch):
    from runner.scanners.container import registry_digest as rd

    monkeypatch.setattr(rd, "_resolve_host", lambda h: ["192.168.1.5"])
    monkeypatch.setattr(
        rd,
        "run_tool",
        lambda args, **kw: pytest.fail("run_tool must not be called"),
    )
    assert rd.fetch_registry_digest("internal-registry.example/x/y:1") is None


def test_registry_digest_rejects_172_16_to_31(monkeypatch):
    from runner.scanners.container import registry_digest as rd

    monkeypatch.setattr(rd, "_resolve_host", lambda h: ["172.20.0.5"])
    monkeypatch.setattr(
        rd,
        "run_tool",
        lambda args, **kw: pytest.fail("run_tool must not be called"),
    )
    assert rd.fetch_registry_digest("internal-registry.example/x/y:1") is None


def test_registry_digest_rejects_127_0_0_1(monkeypatch):
    from runner.scanners.container import registry_digest as rd

    monkeypatch.setattr(rd, "_resolve_host", lambda h: ["127.0.0.1"])
    monkeypatch.setattr(
        rd,
        "run_tool",
        lambda args, **kw: pytest.fail("run_tool must not be called"),
    )
    assert rd.fetch_registry_digest("internal-registry.example/x/y:1") is None


def test_registry_digest_rejects_169_254_link_local(monkeypatch):
    from runner.scanners.container import registry_digest as rd

    monkeypatch.setattr(rd, "_resolve_host", lambda h: ["169.254.10.10"])
    monkeypatch.setattr(
        rd,
        "run_tool",
        lambda args, **kw: pytest.fail("run_tool must not be called"),
    )
    assert rd.fetch_registry_digest("link-local.example/x/y:1") is None


def test_registry_digest_parses_docker_content_digest_header(monkeypatch):
    """Successful HEAD response yields the Docker-Content-Digest value."""
    from runner.scanners.container import registry_digest as rd

    monkeypatch.setattr(rd, "_resolve_host", lambda h: ["93.184.216.34"])
    monkeypatch.setattr(rd, "_read_docker_password", lambda *a, **kw: None)

    raw_response = (
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: application/vnd.oci.image.index.v1+json\r\n"
        "Docker-Content-Digest: sha256:0123456789abcdef\r\n"
        "Content-Length: 123\r\n"
    )
    monkeypatch.setattr(rd, "run_tool", lambda args, **kw: (0, raw_response, ""))

    assert (
        rd.fetch_registry_digest("gcr.io/proj/img:1.0")
        == "sha256:0123456789abcdef"
    )


def test_registry_digest_unparseable_ref_returns_none():
    from runner.scanners.container import registry_digest as rd

    # No '/' in the ref — registry HEAD requires an explicit registry host.
    assert rd.fetch_registry_digest("alpine:3.18") is None


def test_registry_digest_includes_docker_config_auth(tmp_path, monkeypatch):
    """When auth is configured for the registry, it must be sent in headers."""
    from runner.scanners.container import registry_digest as rd

    monkeypatch.setattr(rd, "_resolve_host", lambda h: ["93.184.216.34"])

    config = tmp_path / "config.json"
    config.write_text(
        json.dumps({"auths": {"gcr.io": {"username": "_token", "password": "pw"}}})
    )

    seen_args: list = []

    def fake_run_tool(args, **kw):
        seen_args.append(list(args))
        if "-sfI" in args:
            return (
                0,
                "Docker-Content-Digest: sha256:abc\r\n",
                "",
            )
        # Token exchange request.
        return 0, json.dumps({"token": "bearer-xyz"}), ""

    monkeypatch.setattr(rd, "run_tool", fake_run_tool)

    digest = rd.fetch_registry_digest(
        "gcr.io/proj/img:1.0", docker_config=config
    )
    assert digest == "sha256:abc"
    head_call = next(c for c in seen_args if "-sfI" in c)
    assert any("Authorization: Bearer bearer-xyz" == h for h in head_call)


def test_registry_digest_falls_back_to_basic_auth_when_token_fails(
    tmp_path, monkeypatch
):
    """If token exchange fails, fall back to basic auth header."""
    from runner.scanners.container import registry_digest as rd

    monkeypatch.setattr(rd, "_resolve_host", lambda h: ["93.184.216.34"])
    config = tmp_path / "config.json"
    config.write_text(
        json.dumps({"auths": {"gcr.io": {"password": "pw"}}})
    )

    def fake_run_tool(args, **kw):
        if "-sfI" in args:
            return 0, "Docker-Content-Digest: sha256:basic\r\n", ""
        return 1, "", "token exchange failed"

    monkeypatch.setattr(rd, "run_tool", fake_run_tool)
    assert (
        rd.fetch_registry_digest("gcr.io/proj/img:1.0", docker_config=config)
        == "sha256:basic"
    )


def test_registry_digest_no_digest_header_returns_none(monkeypatch):
    from runner.scanners.container import registry_digest as rd

    monkeypatch.setattr(rd, "_resolve_host", lambda h: ["93.184.216.34"])
    monkeypatch.setattr(rd, "_read_docker_password", lambda *a, **kw: None)
    monkeypatch.setattr(
        rd,
        "run_tool",
        lambda args, **kw: (0, "HTTP/1.1 200 OK\r\nContent-Type: x\r\n", ""),
    )
    assert rd.fetch_registry_digest("gcr.io/proj/img:1.0") is None


def test_registry_digest_times_out(monkeypatch):
    """A timed-out curl propagates as a ScannerTimeoutError from run_tool;
    fetch_registry_digest does not catch it — caller decides."""
    from runner.scanners._subprocess import ScannerTimeoutError
    from runner.scanners.container import registry_digest as rd

    monkeypatch.setattr(rd, "_resolve_host", lambda h: ["93.184.216.34"])
    monkeypatch.setattr(rd, "_read_docker_password", lambda *a, **kw: None)

    def boom(*a, **kw):
        raise ScannerTimeoutError("curl exceeded timeout")

    monkeypatch.setattr(rd, "run_tool", boom)
    with pytest.raises(ScannerTimeoutError):
        rd.fetch_registry_digest("gcr.io/proj/img:1.0")


# ---------------------------------------------------------------------------
# Gap 3 — advisories_only scan mode
# ---------------------------------------------------------------------------


def test_advisories_only_is_supported_mode():
    from runner.scanners.container.scanner import (
        SCAN_MODE_ADVISORIES_ONLY,
        SCAN_MODE_FULL,
        SUPPORTED_SCAN_MODES,
    )

    assert SCAN_MODE_FULL in SUPPORTED_SCAN_MODES
    assert SCAN_MODE_ADVISORIES_ONLY in SUPPORTED_SCAN_MODES


def test_run_scan_advisories_only_skips_syft(tmp_path, monkeypatch):
    """In advisories_only mode, syft must NOT be invoked."""
    from runner.scanners.container import scanner as scanner_mod
    from runner.scanners.container.scanner import ContainerScanner

    monkeypatch.setattr(ContainerScanner, "_ensure_grype_db", lambda self, c: None)
    monkeypatch.setattr(
        scanner_mod.registry_auth, "configure_registry_auth", lambda: 0
    )

    syft_calls: list = []
    monkeypatch.setattr(
        ContainerScanner,
        "_run_syft",
        lambda self, *a, **kw: syft_calls.append(a) or True,
    )

    def fake_download(image_ref, output_path, *, backend_client, job_id):
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(
            json.dumps({"metadata": {"component": {"name": image_ref}}})
        )
        return output_path

    monkeypatch.setattr(
        scanner_mod.download_sbom, "download_sbom_for_image", fake_download
    )
    grype_calls: list = []

    def fake_grype(self, sbom, output, cancel_event):
        grype_calls.append(sbom)
        output.write_text(
            json.dumps(
                {
                    "matches": [
                        {
                            "vulnerability": {"id": "CVE-2024-9"},
                            "artifact": {
                                "name": "p",
                                "version": "1",
                                "type": "deb",
                            },
                        }
                    ]
                }
            )
        )
        return True

    monkeypatch.setattr(ContainerScanner, "_run_grype", fake_grype)

    scanner = ContainerScanner()
    job = {
        "jobId": "adv-only",
        "_backend": object(),
        "envVars": {
                "DOCKER_IMAGES": "gcr.io/proj/img:1.0",
                "SCAN_MODE": "advisories_only",
                "ORG_LABEL": "acme",
            },
    }
    result = scanner.run_scan(job, job_dir=tmp_path / "adv-only")
    assert result.exit_code == 0
    assert syft_calls == []
    assert len(grype_calls) == 1


def test_run_scan_advisories_only_normalizes_findings(tmp_path, monkeypatch):
    from runner.scanners.container import scanner as scanner_mod
    from runner.scanners.container.scanner import ContainerScanner

    monkeypatch.setattr(ContainerScanner, "_ensure_grype_db", lambda self, c: None)
    monkeypatch.setattr(
        scanner_mod.registry_auth, "configure_registry_auth", lambda: 0
    )

    def fake_download(image_ref, output_path, *, backend_client, job_id):
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(
            json.dumps({"metadata": {"component": {"name": image_ref}}})
        )
        return output_path

    monkeypatch.setattr(
        scanner_mod.download_sbom, "download_sbom_for_image", fake_download
    )

    def fake_grype(self, sbom, output, cancel_event):
        output.write_text(
            json.dumps(
                {
                    "matches": [
                        {
                            "vulnerability": {
                                "id": "CVE-2024-100",
                                "severity": "High",
                            },
                            "artifact": {
                                "name": "openssl",
                                "version": "1.0",
                                "type": "deb",
                            },
                        }
                    ]
                }
            )
        )
        return True

    monkeypatch.setattr(ContainerScanner, "_run_grype", fake_grype)

    scanner = ContainerScanner()
    job = {
        "jobId": "adv-norm",
        "_backend": object(),
        "envVars": {
                "DOCKER_IMAGES": "gcr.io/proj/img:1.0",
                "SCAN_MODE": "advisories_only",
                "ORG_LABEL": "acme",
            },
    }
    job_dir = tmp_path / "adv-norm"
    scanner.run_scan(job, job_dir=job_dir)
    lines = (job_dir / "findings.jsonl").read_text().splitlines()
    assert len(lines) == 1
    finding = json.loads(lines[0])
    assert finding["advisoryId"] == "CVE-2024-100"
    assert finding["severity"] == "high"
    assert finding["organization"] == "acme"


def test_run_scan_advisories_only_writes_done_marker(tmp_path, monkeypatch):
    from runner.scanners.container import scanner as scanner_mod
    from runner.scanners.container.scanner import ContainerScanner

    monkeypatch.setattr(ContainerScanner, "_ensure_grype_db", lambda self, c: None)
    monkeypatch.setattr(
        scanner_mod.registry_auth, "configure_registry_auth", lambda: 0
    )
    monkeypatch.setattr(
        scanner_mod.download_sbom,
        "download_sbom_for_image",
        lambda image_ref, output_path, **kw: output_path.write_text("{}")
        or output_path,
    )
    monkeypatch.setattr(
        ContainerScanner,
        "_run_grype",
        lambda self, sbom, output, cancel_event: output.write_text(
            json.dumps({"matches": []})
        )
        or True,
    )

    scanner = ContainerScanner()
    job = {
        "jobId": "adv-done",
        "_backend": object(),
        "envVars": {
                "DOCKER_IMAGES": "gcr.io/proj/img:1.0",
                "SCAN_MODE": "advisories_only",
                "ORG_LABEL": "acme",
            },
    }
    job_dir = tmp_path / "adv-done"
    scanner.run_scan(job, job_dir=job_dir)
    manifest = (job_dir / "_manifest.jsonl").read_text()
    assert '"file": "_done"' in manifest


def test_run_scan_advisories_only_emits_progress(tmp_path, monkeypatch):
    from runner.scanners.container import scanner as scanner_mod
    from runner.scanners.container.scanner import ContainerScanner

    monkeypatch.setattr(ContainerScanner, "_ensure_grype_db", lambda self, c: None)
    monkeypatch.setattr(
        scanner_mod.registry_auth, "configure_registry_auth", lambda: 0
    )

    def fake_download(image_ref, output_path, *, backend_client, job_id):
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text("{}")
        return output_path

    monkeypatch.setattr(
        scanner_mod.download_sbom, "download_sbom_for_image", fake_download
    )
    monkeypatch.setattr(
        ContainerScanner,
        "_run_grype",
        lambda self, sbom, output, cancel_event: output.write_text(
            json.dumps({"matches": []})
        )
        or True,
    )

    captures: list[dict] = []
    scanner = ContainerScanner()
    job = {
        "jobId": "adv-progress",
        "_backend": object(),
        "envVars": {
                "DOCKER_IMAGES": "gcr.io/proj/a:1.0,gcr.io/proj/b:1.0",
                "SCAN_MODE": "advisories_only",
                "ORG_LABEL": "acme",
                "CONCURRENCY": "1",
            },
    }
    scanner.run_scan(
        job,
        job_dir=tmp_path / "adv-progress",
        on_progress=lambda lt, p: captures.append(dict(p)),
    )
    assert captures[-1]["stage"] == "done"
    assert captures[-1]["finishedRepos"] == 2
    assert any(c.get("stage") == "scanning" for c in captures)
    assert any(c.get("stage") == "normalizing" for c in captures)


def test_run_scan_advisories_only_continues_when_sbom_unavailable(
    tmp_path, monkeypatch
):
    """A missing SBOM is logged but does NOT abort the overall scan."""
    from runner.scanners.container import scanner as scanner_mod
    from runner.scanners.container.scanner import ContainerScanner
    from runner.scanners.container.download_sbom import SbomDownloadError

    monkeypatch.setattr(ContainerScanner, "_ensure_grype_db", lambda self, c: None)
    monkeypatch.setattr(
        scanner_mod.registry_auth, "configure_registry_auth", lambda: 0
    )

    def fail_download(image_ref, output_path, **kw):
        raise SbomDownloadError(f"no SBOM for {image_ref}")

    monkeypatch.setattr(
        scanner_mod.download_sbom, "download_sbom_for_image", fail_download
    )

    grype_calls: list = []
    monkeypatch.setattr(
        ContainerScanner,
        "_run_grype",
        lambda self, *a, **kw: grype_calls.append(a) or True,
    )

    scanner = ContainerScanner()
    job = {
        "jobId": "adv-miss",
        "_backend": object(),
        "envVars": {
                "DOCKER_IMAGES": "gcr.io/proj/img:1.0",
                "SCAN_MODE": "advisories_only",
                "ORG_LABEL": "acme",
            },
    }
    result = scanner.run_scan(job, job_dir=tmp_path / "adv-miss")
    # No SBOM → no grype call.
    assert grype_calls == []
    assert result.exit_code == 0
    assert any("No stored SBOM" in line for line in result.log_tail)


def test_download_sbom_raises_when_listing_missing_image(tmp_path):
    """If the backend listing has no entry for the image, raise SbomDownloadError."""
    from runner.scanners.container.download_sbom import (
        SbomDownloadError,
        download_sbom_for_image,
    )

    class _BackendStub:
        def list_sbom_downloads(self, job_id):
            return [{"file": "other__sbom.cdx.json", "url": "https://example/x"}]

    with pytest.raises(SbomDownloadError):
        download_sbom_for_image(
            "gcr.io/proj/img:1.0",
            tmp_path / "sbom.cdx.json",
            backend_client=_BackendStub(),
            job_id="job-1",
        )


def test_download_sbom_uses_expected_listing_filename(tmp_path, monkeypatch):
    """Verify the listing filename shape: <sanitized_ref>__sbom.cdx.json."""
    from runner.scanners.container import download_sbom as ds_mod

    seen: dict = {}

    class _BackendStub:
        def list_sbom_downloads(self, job_id):
            seen["job_id"] = job_id
            return [
                {
                    "file": "gcr.io_proj_img_1.0__sbom.cdx.json",
                    "url": "https://minio.example/signed",
                },
                {
                    "file": "other_image__sbom.cdx.json",
                    "url": "https://minio.example/other",
                },
            ]

    class _FakeResp:
        status_code = 200
        content = b'{"metadata": {}}'

    class _FakeClient:
        def __init__(self, *a, **kw):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def get(self, url):
            seen["url"] = url
            return _FakeResp()

    monkeypatch.setattr(ds_mod.httpx, "Client", _FakeClient)

    out = tmp_path / "sub" / "sbom.cdx.json"
    ds_mod.download_sbom_for_image(
        "gcr.io/proj/img:1.0",
        out,
        backend_client=_BackendStub(),
        job_id="job-xyz",
    )
    assert seen["job_id"] == "job-xyz"
    assert seen["url"] == "https://minio.example/signed"
    assert out.exists()
    assert out.read_bytes() == b'{"metadata": {}}'


# ---------------------------------------------------------------------------
# Task 3.4 / 3.5 — sbom_only scan mode (skip_grype)
# ---------------------------------------------------------------------------


def test_scan_image_skip_grype_returns_none(tmp_path, monkeypatch):
    """When skip_grype=True, _scan_image builds SBOM, registers it, skips grype.

    Bash reference (scanners/container/run.sh:210-214): SCAN_MODE=sbom_only
    runs syft, calls register_output for the SBOM, calls log_finished, and
    returns — no grype, no findings.json, no digest.txt.
    """
    from runner.scanners.container.scanner import ContainerScanner

    scanner = ContainerScanner()
    grype_called: list[str] = []

    def fake_run_syft(self, image_ref, scan_platform, output, cancel_event, **_):
        output.write_text(json.dumps({"components": []}))
        return True

    def fake_run_grype(self, sbom, output, cancel_event):
        grype_called.append(str(sbom))
        return True

    monkeypatch.setattr(ContainerScanner, "_run_syft", fake_run_syft)
    monkeypatch.setattr(ContainerScanner, "_run_grype", fake_run_grype)

    out_dir = tmp_path / "out"
    out_dir.mkdir()

    result = scanner._scan_image(
        "alpine:3.18",
        out_dir,
        scan_platform="linux/amd64",
        cancel_event=threading.Event(),
        previous_digests=None,
        log_tail=[],
        skip_grype=True,
    )

    assert result is None
    assert grype_called == []
    # SBOM was still written + registered
    assert (out_dir / "alpine_3.18" / "sbom.cdx.json").exists()


def test_scan_image_skip_grype_default_false_still_runs_grype(tmp_path, monkeypatch):
    """Default skip_grype=False keeps the full flow — regression guard."""
    from runner.scanners.container.scanner import ContainerScanner

    scanner = ContainerScanner()
    grype_called: list[str] = []

    def fake_run_syft(self, image_ref, scan_platform, output, cancel_event, **_):
        output.write_text(json.dumps({"components": []}))
        return True

    def fake_run_grype(self, sbom, output, cancel_event):
        grype_called.append(str(sbom))
        output.write_text("{}")
        return True

    monkeypatch.setattr(ContainerScanner, "_run_syft", fake_run_syft)
    monkeypatch.setattr(ContainerScanner, "_run_grype", fake_run_grype)

    out_dir = tmp_path / "out"
    out_dir.mkdir()

    result = scanner._scan_image(
        "alpine:3.18",
        out_dir,
        scan_platform="linux/amd64",
        cancel_event=threading.Event(),
        previous_digests=None,
        log_tail=[],
    )

    assert result is not None
    assert len(grype_called) == 1


def test_run_scan_sbom_only_skips_grype_per_image(tmp_path, monkeypatch):
    """Container sbom_only: SBOM built per image, grype not invoked, _done written.

    Bash reference: SCAN_MODE=sbom_only in run.sh:210-214 produces only
    sbom.cdx.json per image — no findings.json, so the normalization loop
    (run.sh:322-335) skips and no findings.jsonl is written.
    """
    from runner.scanners.container.scanner import ContainerScanner

    scanner = ContainerScanner()
    grype_called: list[str] = []
    scan_image_calls: list[tuple[str, bool]] = []

    def fake_scan_image(
        self, image_ref, out_dir, *, scan_platform, cancel_event,
        previous_digests=None, log_tail=None, skip_grype=False,
    ):
        scan_image_calls.append((image_ref, skip_grype))
        if skip_grype:
            return None
        grype_called.append(image_ref)
        return out_dir / "findings.json"

    monkeypatch.setattr(ContainerScanner, "_scan_image", fake_scan_image)
    monkeypatch.setattr(
        ContainerScanner, "_ensure_grype_db", lambda self, c: None
    )

    job = {
        "jobId": "sbom-img",
        "envVars": {
            "DOCKER_IMAGES": "alpine:3.18",
            "SCAN_MODE": "sbom_only",
        },
    }
    job_dir = tmp_path / "sbom-img"
    result = scanner.run_scan(job, job_dir=job_dir)

    assert result.exit_code == 0
    assert grype_called == []
    assert scan_image_calls and all(skip for _, skip in scan_image_calls)
    manifest = (job_dir / "_manifest.jsonl").read_text()
    assert '"file": "_done"' in manifest
    assert not (job_dir / "findings.jsonl").exists()


def test_run_scan_sbom_only_container_emits_progress(tmp_path, monkeypatch):
    """Container sbom_only emits final progress event with stage='done'."""
    from runner.scanners.container.scanner import ContainerScanner

    scanner = ContainerScanner()
    progress_events: list[dict] = []

    def fake_scan_image(self, *args, **kwargs):
        return None

    monkeypatch.setattr(ContainerScanner, "_scan_image", fake_scan_image)
    monkeypatch.setattr(
        ContainerScanner, "_ensure_grype_db", lambda self, c: None
    )

    job = {
        "jobId": "sbom-img-prog",
        "envVars": {
            "DOCKER_IMAGES": "alpine:3.18,nginx:1.25",
            "SCAN_MODE": "sbom_only",
        },
    }
    scanner.run_scan(
        job, job_dir=tmp_path / "sbom-img-prog",
        on_progress=lambda log, prog: progress_events.append(dict(prog)),
    )

    assert any(p.get("stage") == "done" for p in progress_events)
    final = progress_events[-1]
    assert final["finishedRepos"] == final["expectedRepos"] == 2


def test_container_sbom_only_in_supported_modes():
    """sbom_only must be listed in container SUPPORTED_SCAN_MODES."""
    from runner.scanners.container.scanner import (
        DEFERRED_SCAN_MODES,
        SUPPORTED_SCAN_MODES,
    )

    assert "sbom_only" in SUPPORTED_SCAN_MODES
    assert "sbom_only" not in DEFERRED_SCAN_MODES


# ---------------------------------------------------------------------------
# ContainerScanConfig
# ---------------------------------------------------------------------------

def _container_job(env: dict) -> dict:
    return {"jobId": "job-test", "envVars": env}


def test_container_config_parses_defaults():
    from runner.scanners.container.scanner import ContainerScanConfig
    cfg = ContainerScanConfig.from_job(_container_job({"DOCKER_IMAGES": "alpine:3.18"}))
    assert cfg.org_label == "default"
    assert cfg.concurrency == 4
    assert cfg.scan_mode == "full"
    assert cfg.scan_platform == "linux/amd64"
    assert cfg.previous_digests_raw == ""
    assert cfg.images == ["alpine:3.18"]


def test_container_config_parses_explicit_values():
    from runner.scanners.container.scanner import ContainerScanConfig
    cfg = ContainerScanConfig.from_job(_container_job({
        "DOCKER_IMAGES": "alpine:3.18,nginx:latest",
        "ORG_LABEL": "acme-org",
        "CONCURRENCY": "6",
        "SCAN_MODE": "advisories_only",
        "SCAN_PLATFORM": "linux/arm64",
        "PREVIOUS_DIGESTS": "sha256:abc",
    }))
    assert cfg.images == ["alpine:3.18", "nginx:latest"]
    assert cfg.org_label == "acme-org"
    assert cfg.concurrency == 6
    assert cfg.scan_mode == "advisories_only"
    assert cfg.scan_platform == "linux/arm64"
    assert cfg.previous_digests_raw == "sha256:abc"


def test_container_config_rejects_unsupported_scan_mode():
    from runner.scanners._shared import ScannerConfigError
    from runner.scanners.container.scanner import ContainerScanConfig
    with pytest.raises(ScannerConfigError, match="SCAN_MODE"):
        ContainerScanConfig.from_job(_container_job({
            "DOCKER_IMAGES": "alpine:3.18",
            "SCAN_MODE": "unknown_mode",
        }))


def test_container_config_run_id_falls_back_to_job_id():
    from runner.scanners.container.scanner import ContainerScanConfig
    cfg = ContainerScanConfig.from_job({"jobId": "job-88", "envVars": {"DOCKER_IMAGES": "alpine:3.18"}})
    assert cfg.run_id == "job-88"
