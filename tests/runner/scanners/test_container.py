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


# ---------------------------------------------------------------------------
# Task 3.3 — ContainerScanner orchestrator
# ---------------------------------------------------------------------------


def test_container_scanner_has_correct_type():
    from runner.scanners.container.scanner import ContainerScanner

    assert ContainerScanner.SCANNER_TYPE == "container_scanning"


def test_container_scanner_exposes_run_scan():
    from runner.scanners.container.scanner import ContainerScanner

    scanner = ContainerScanner()
    assert hasattr(scanner, "run_scan") and callable(scanner.run_scan)
    assert scanner.SCANNER_TYPE == "container_scanning"


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


# ---------------------------------------------------------------------------
# Gap 2 — Registry HEAD digest fallback (SSRF-guarded)
# ---------------------------------------------------------------------------


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


def test_registry_digest_rejects_cgnat(monkeypatch):
    from runner.scanners.container import registry_digest as rd

    # RFC 6598 CGNAT — not flagged private by stdlib ipaddress; can host metadata
    # on some clouds. Must be blocked the same as RFC1918.
    monkeypatch.setattr(rd, "_resolve_host", lambda h: ["100.100.100.200"])
    monkeypatch.setattr(
        rd,
        "run_tool",
        lambda args, **kw: pytest.fail("run_tool must not be called"),
    )
    assert rd.fetch_registry_digest("internal-registry.example/x/y:1") is None


def test_is_blocked_ip_rejects_cgnat_range():
    from runner.scanners.container.registry_digest import _is_blocked_ip

    assert _is_blocked_ip("100.100.100.200") is True
    assert _is_blocked_ip("100.64.0.1") is True
    assert _is_blocked_ip("100.127.255.254") is True
    # Public addresses remain allowed.
    assert _is_blocked_ip("93.184.216.34") is False


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


def test_list_tags_parses_tag_list(monkeypatch):
    from runner.scanners.container import registry_digest as rd

    monkeypatch.setattr(rd, "_resolve_host", lambda h: ["93.184.216.34"])
    monkeypatch.setattr(rd, "_read_docker_password", lambda *a, **kw: None)
    calls = {}

    def _fake_run(args, **kw):
        calls["url"] = args[-1]
        return (0, '{"name":"acme/app","tags":["1.0.0","1.1.0","latest"]}', "")

    monkeypatch.setattr(rd, "run_tool", _fake_run)
    tags = rd.list_tags("ghcr.io/acme/app:1.0.0")
    assert tags == ["1.0.0", "1.1.0", "latest"]
    assert calls["url"] == "https://ghcr.io/v2/acme/app/tags/list"


def test_list_tags_returns_none_on_curl_failure(monkeypatch):
    from runner.scanners.container import registry_digest as rd

    monkeypatch.setattr(rd, "_resolve_host", lambda h: ["93.184.216.34"])
    monkeypatch.setattr(rd, "_read_docker_password", lambda *a, **kw: None)
    monkeypatch.setattr(rd, "run_tool", lambda args, **kw: (1, "", "boom"))
    assert rd.list_tags("ghcr.io/acme/app:1.0.0") is None


def test_list_tags_rejects_ssrf_hosts(monkeypatch):
    from runner.scanners.container import registry_digest as rd

    monkeypatch.setattr(
        rd, "run_tool", lambda args, **kw: pytest.fail("run_tool must not be called")
    )
    assert rd.list_tags("localhost/x/y:1") is None
    assert rd.list_tags("169.254.169.254/x/y:1") is None
