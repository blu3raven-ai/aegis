"""Tests for Phase 9 real scanner adapters.

All tests mock subprocess.run / shutil.which so they pass without the actual
binaries installed. Integration tests that require real binaries are marked
with skipif guards.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest


@pytest.fixture(autouse=True)
def _reset_checkout_upload_singleton():
    """The shared checkout_upload helper caches a boto3 client at module scope.
    Tests that stub boto3 via sys.modules would otherwise leak the stub into
    later tests through the singleton — reset before each test for isolation.
    """
    from src.shared import checkout_upload

    checkout_upload._reset_s3_client_for_tests()
    yield
    checkout_upload._reset_s3_client_for_tests()


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _make_completed(stdout: str = "", returncode: int = 0) -> subprocess.CompletedProcess:
    cp = MagicMock(spec=subprocess.CompletedProcess)
    cp.stdout = stdout
    cp.stderr = ""
    cp.returncode = returncode
    return cp


# ---------------------------------------------------------------------------
# subprocess_runner shared helper
# ---------------------------------------------------------------------------

class TestSubprocessRunner:
    def test_raises_unavailable_when_binary_missing(self):
        from src.shared.subprocess_runner import AdapterUnavailableError, run_subprocess

        with patch("shutil.which", return_value=None):
            with pytest.raises(AdapterUnavailableError, match="not found on PATH"):
                run_subprocess(["syft", "some/path"])

    def test_raises_failed_on_nonzero_exit(self):
        from src.shared.subprocess_runner import AdapterFailedError, run_subprocess

        cp = _make_completed(stdout="", returncode=2)
        cp.stderr = "some error"

        with patch("shutil.which", return_value="/usr/local/bin/syft"), \
             patch("subprocess.run", return_value=cp):
            with pytest.raises(AdapterFailedError) as exc_info:
                run_subprocess(["syft", "some/path"])
            assert exc_info.value.returncode == 2

    def test_returns_completed_process_on_success(self):
        from src.shared.subprocess_runner import run_subprocess

        cp = _make_completed(stdout='{"components": []}', returncode=0)
        with patch("shutil.which", return_value="/usr/local/bin/syft"), \
             patch("subprocess.run", return_value=cp):
            result = run_subprocess(["syft", "some/path"])
        assert result.stdout == '{"components": []}'

    def test_file_not_found_raises_unavailable(self):
        from src.shared.subprocess_runner import AdapterUnavailableError, run_subprocess

        with patch("shutil.which", return_value="/usr/local/bin/syft"), \
             patch("subprocess.run", side_effect=FileNotFoundError):
            with pytest.raises(AdapterUnavailableError, match="may have been removed"):
                run_subprocess(["syft", "some/path"])


# ---------------------------------------------------------------------------
# dependencies/syft_adapter (HTTP transport — Phase 7 Step 4)
# ---------------------------------------------------------------------------

class TestDepsSyftAdapter:
    def _patch_transport(self, handler):
        import httpx

        from src.shared import scanner_http_client as shc

        real_client_cls = shc.ScannerHttpClient

        def _factory(*args, **kwargs):
            kwargs["transport"] = httpx.MockTransport(handler)
            return real_client_cls(*args, **kwargs)

        return patch.object(
            __import__("src.dependencies.syft_adapter", fromlist=["ScannerHttpClient"]),
            "ScannerHttpClient",
            _factory,
        )

    def test_mount_transport_sends_workspace_uri(self, monkeypatch):
        import httpx

        from src.dependencies.syft_adapter import run_syft

        monkeypatch.setenv("SCANNER_DEPS_URL", "http://deps:8081")
        monkeypatch.setenv("CHECKOUT_TRANSPORT", "mount")

        sbom = {"bomFormat": "CycloneDX", "components": []}
        captured = {}

        def handler(request: httpx.Request) -> httpx.Response:
            captured["payload"] = json.loads(request.content)
            captured["path"] = request.url.path
            return httpx.Response(200, json={"sbom": sbom})

        with self._patch_transport(handler):
            result = run_syft(Path("/workspace/scan-1/repo-a"))

        assert result == sbom
        assert captured["path"] == "/v1/sbom"
        assert captured["payload"] == {"checkout_ref": "workspace://scan-1/repo-a"}

    def test_mount_transport_rejects_path_outside_workspace(self, monkeypatch):
        from src.dependencies.syft_adapter import AdapterUnavailableError, run_syft

        monkeypatch.setenv("SCANNER_DEPS_URL", "http://deps:8081")
        monkeypatch.setenv("CHECKOUT_TRANSPORT", "mount")

        with pytest.raises(AdapterUnavailableError):
            run_syft(Path("/tmp/some-other-dir"))

    def test_minio_transport_uploads_and_sends_key(self, monkeypatch, tmp_path):
        import sys
        import httpx

        from src.dependencies.syft_adapter import run_syft

        monkeypatch.setenv("SCANNER_DEPS_URL", "http://deps:8081")
        monkeypatch.setenv("CHECKOUT_TRANSPORT", "minio")
        monkeypatch.setenv("S3_ENDPOINT", "http://minio:9000")
        monkeypatch.setenv("S3_ACCESS_KEY", "k")
        monkeypatch.setenv("S3_SECRET_KEY", "s")

        # Real checkout dir so the tarball build succeeds.
        checkout = tmp_path / "scan-9" / "repo-z"
        checkout.mkdir(parents=True)
        (checkout / "package.json").write_text('{}')

        fake_s3 = MagicMock()
        fake_s3.head_bucket.return_value = {}
        sbom = {"bomFormat": "CycloneDX"}

        def handler(request: httpx.Request) -> httpx.Response:
            payload = json.loads(request.content)
            assert "checkout_minio_key" in payload
            assert payload["checkout_minio_key"].startswith("aegis-checkouts/")
            return httpx.Response(200, json={"sbom": sbom})

        # boto3 is imported lazily inside the adapter; stub it via sys.modules.
        fake_boto3 = MagicMock()
        fake_boto3.client = lambda *a, **kw: fake_s3
        monkeypatch.setitem(sys.modules, "boto3", fake_boto3)

        with self._patch_transport(handler):
            result = run_syft(checkout)

        assert result == sbom
        put_calls = fake_s3.put_object.call_args_list
        assert len(put_calls) == 1
        assert put_calls[0].kwargs["Bucket"] == "aegis-checkouts"
        # Canonical key layout is now <scanner>/<uuid>.tar.gz; the brittle
        # parts[-2:] derivation that put repo-z in the key was dropped in
        # favour of a UUID that survives concurrent scans without collision.
        assert put_calls[0].kwargs["Key"].startswith("dependencies/")
        assert put_calls[0].kwargs["Key"].endswith(".tar.gz")

    def test_minio_transport_missing_creds_raises_unavailable(self, monkeypatch, tmp_path):
        from src.dependencies.syft_adapter import AdapterUnavailableError, run_syft

        monkeypatch.setenv("SCANNER_DEPS_URL", "http://deps:8081")
        monkeypatch.setenv("CHECKOUT_TRANSPORT", "minio")
        monkeypatch.delenv("S3_ENDPOINT", raising=False)
        monkeypatch.delenv("S3_ACCESS_KEY", raising=False)
        monkeypatch.delenv("S3_SECRET_KEY", raising=False)

        with pytest.raises(AdapterUnavailableError, match="S3_"):
            run_syft(tmp_path)

    def test_minio_transport_operation_failure_raises_failed(self, monkeypatch, tmp_path):
        """MinIO operational failures (e.g. bucket-ensure / put_object errors)
        must surface as AdapterFailedError so the engine reports the real
        failure instead of silently falling through to the full-scan path.
        """
        from src.dependencies import syft_adapter
        from src.dependencies.syft_adapter import AdapterFailedError, run_syft
        from src.shared.checkout_upload import MinioOperationFailed

        monkeypatch.setenv("SCANNER_DEPS_URL", "http://deps:8081")
        monkeypatch.setenv("CHECKOUT_TRANSPORT", "minio")

        checkout = tmp_path / "scan-fail" / "repo-q"
        checkout.mkdir(parents=True)

        def boom(*_args, **_kwargs):
            raise MinioOperationFailed("put_object failed for aegis-checkouts/x: oops")

        monkeypatch.setattr(syft_adapter, "upload_checkout", boom)

        with pytest.raises(AdapterFailedError, match="put_object failed"):
            run_syft(checkout)

    def test_http_4xx_raises_failed(self, monkeypatch):
        import httpx

        from src.dependencies.syft_adapter import AdapterFailedError, run_syft

        monkeypatch.setenv("SCANNER_DEPS_URL", "http://deps:8081")
        monkeypatch.setenv("CHECKOUT_TRANSPORT", "mount")

        def handler(request):
            return httpx.Response(400, text="bad")

        with self._patch_transport(handler):
            with pytest.raises(AdapterFailedError):
                run_syft(Path("/workspace/scan-1/repo-a"))

    def test_http_503_raises_unavailable(self, monkeypatch):
        import httpx

        from src.dependencies.syft_adapter import AdapterUnavailableError, run_syft

        monkeypatch.setenv("SCANNER_DEPS_URL", "http://deps:8081")
        monkeypatch.setenv("CHECKOUT_TRANSPORT", "mount")

        def handler(request):
            return httpx.Response(503, text="overloaded")

        with self._patch_transport(handler):
            with pytest.raises(AdapterUnavailableError):
                run_syft(Path("/workspace/scan-1/repo-a"))

    def test_connect_error_raises_unavailable(self, monkeypatch):
        import httpx

        from src.dependencies.syft_adapter import AdapterUnavailableError, run_syft

        monkeypatch.setenv("SCANNER_DEPS_URL", "http://deps:8081")
        monkeypatch.setenv("CHECKOUT_TRANSPORT", "mount")

        def handler(request):
            raise httpx.ConnectError("cannot connect")

        with self._patch_transport(handler):
            with pytest.raises(AdapterUnavailableError):
                run_syft(Path("/workspace/scan-1/repo-a"))

    def test_env_unset_raises_unavailable(self, monkeypatch):
        from src.dependencies.syft_adapter import AdapterUnavailableError, run_syft

        monkeypatch.setenv("CHECKOUT_TRANSPORT", "mount")
        monkeypatch.delenv("SCANNER_DEPS_URL", raising=False)

        with pytest.raises(AdapterUnavailableError):
            run_syft(Path("/workspace/scan-1/repo-a"))


# ---------------------------------------------------------------------------
# dependencies/grype_adapter (HTTP transport — Phase 7 Step 3)
# ---------------------------------------------------------------------------

class TestDepsGrypeAdapter:
    def _patch_transport(self, handler):
        """Build a ScannerHttpClient factory backed by httpx.MockTransport."""
        import httpx

        from src.shared import scanner_http_client as shc

        real_client_cls = shc.ScannerHttpClient

        def _factory(*args, **kwargs):
            kwargs["transport"] = httpx.MockTransport(handler)
            return real_client_cls(*args, **kwargs)

        return patch.object(
            __import__("src.dependencies.grype_adapter", fromlist=["ScannerHttpClient"]),
            "ScannerHttpClient",
            _factory,
        )

    def test_returns_matches_list(self, monkeypatch):
        import httpx

        from src.dependencies.grype_adapter import run_grype

        monkeypatch.setenv("SCANNER_DEPS_URL", "http://deps:8081")

        matches = [{"vulnerability": {"id": "CVE-2023-1234"}}]
        captured = {}

        def handler(request: httpx.Request) -> httpx.Response:
            captured["path"] = request.url.path
            captured["payload"] = json.loads(request.content)
            return httpx.Response(200, json={"matches": matches})

        with self._patch_transport(handler):
            result = run_grype({"bomFormat": "CycloneDX"})

        assert result == matches
        assert captured["path"] == "/v1/match"
        assert captured["payload"] == {"sbom": {"bomFormat": "CycloneDX"}}

    def test_raises_failed_on_4xx(self, monkeypatch):
        import httpx

        from src.dependencies.grype_adapter import AdapterFailedError, run_grype

        monkeypatch.setenv("SCANNER_DEPS_URL", "http://deps:8081")

        def handler(request):
            return httpx.Response(400, text="bad request")

        with self._patch_transport(handler):
            with pytest.raises(AdapterFailedError):
                run_grype({"bomFormat": "CycloneDX"})

    def test_raises_unavailable_on_503(self, monkeypatch):
        import httpx

        from src.dependencies.grype_adapter import AdapterUnavailableError, run_grype

        monkeypatch.setenv("SCANNER_DEPS_URL", "http://deps:8081")

        def handler(request):
            return httpx.Response(503, text="overloaded")

        with self._patch_transport(handler):
            with pytest.raises(AdapterUnavailableError):
                run_grype({"bomFormat": "CycloneDX"})

    def test_raises_unavailable_on_connect_error(self, monkeypatch):
        import httpx

        from src.dependencies.grype_adapter import AdapterUnavailableError, run_grype

        monkeypatch.setenv("SCANNER_DEPS_URL", "http://deps:8081")

        def handler(request):
            raise httpx.ConnectError("cannot connect")

        with self._patch_transport(handler):
            with pytest.raises(AdapterUnavailableError):
                run_grype({"bomFormat": "CycloneDX"})

    def test_raises_unavailable_when_env_unset(self, monkeypatch):
        from src.dependencies.grype_adapter import AdapterUnavailableError, run_grype

        monkeypatch.delenv("SCANNER_DEPS_URL", raising=False)

        with pytest.raises(AdapterUnavailableError):
            run_grype({"bomFormat": "CycloneDX"})

    def test_malformed_matches_field_raises_failed(self, monkeypatch):
        import httpx

        from src.dependencies.grype_adapter import AdapterFailedError, run_grype

        monkeypatch.setenv("SCANNER_DEPS_URL", "http://deps:8081")

        def handler(request):
            return httpx.Response(200, json={"matches": "not a list"})

        with self._patch_transport(handler):
            with pytest.raises(AdapterFailedError):
                run_grype({"bomFormat": "CycloneDX"})

    def test_empty_matches_returns_empty_list(self, monkeypatch):
        import httpx

        from src.dependencies.grype_adapter import run_grype

        monkeypatch.setenv("SCANNER_DEPS_URL", "http://deps:8081")

        def handler(request):
            return httpx.Response(200, json={"matches": []})

        with self._patch_transport(handler):
            result = run_grype({"bomFormat": "CycloneDX"})
        assert result == []


# ---------------------------------------------------------------------------
# containers/syft_adapter (HTTP transport — Phase 7 Step 5)
# ---------------------------------------------------------------------------

class TestContainerSyftAdapter:
    def _patch_transport(self, handler):
        import httpx

        from src.shared import scanner_http_client as shc

        real_client_cls = shc.ScannerHttpClient

        def _factory(*args, **kwargs):
            kwargs["transport"] = httpx.MockTransport(handler)
            return real_client_cls(*args, **kwargs)

        return patch.object(
            __import__("src.containers.syft_adapter", fromlist=["ScannerHttpClient"]),
            "ScannerHttpClient",
            _factory,
        )

    def test_sends_image_pull_ref(self, monkeypatch):
        import httpx

        from src.containers.syft_adapter import run_syft

        monkeypatch.setenv("SCANNER_CONTAINER_URL", "http://container:8081")

        sbom = {"bomFormat": "CycloneDX", "components": []}
        captured = {}

        def handler(request: httpx.Request) -> httpx.Response:
            captured["path"] = request.url.path
            captured["payload"] = json.loads(request.content)
            return httpx.Response(200, json={"sbom": sbom})

        with self._patch_transport(handler):
            result = run_syft("docker.io/library/nginx:1.27")

        assert result == sbom
        assert captured["path"] == "/v1/sbom"
        assert captured["payload"] == {"image_pull_ref": "docker.io/library/nginx:1.27"}

    def test_env_unset_raises_unavailable(self, monkeypatch):
        from src.containers.syft_adapter import AdapterUnavailableError, run_syft

        monkeypatch.delenv("SCANNER_CONTAINER_URL", raising=False)
        with pytest.raises(AdapterUnavailableError):
            run_syft("nginx:1.27")

    def test_503_raises_unavailable(self, monkeypatch):
        import httpx

        from src.containers.syft_adapter import AdapterUnavailableError, run_syft

        monkeypatch.setenv("SCANNER_CONTAINER_URL", "http://container:8081")

        def handler(request):
            return httpx.Response(503, text="busy")

        with self._patch_transport(handler):
            with pytest.raises(AdapterUnavailableError):
                run_syft("nginx:1.27")

    def test_500_raises_failed(self, monkeypatch):
        import httpx

        from src.containers.syft_adapter import AdapterFailedError, run_syft

        monkeypatch.setenv("SCANNER_CONTAINER_URL", "http://container:8081")

        def handler(request):
            return httpx.Response(500, text="syft crash")

        with self._patch_transport(handler):
            with pytest.raises(AdapterFailedError):
                run_syft("nginx:1.27")


# ---------------------------------------------------------------------------
# containers/grype_adapter (HTTP transport — Phase 7 Step 5)
# ---------------------------------------------------------------------------

class TestContainerGrypeAdapter:
    def _patch_transport(self, handler):
        import httpx

        from src.shared import scanner_http_client as shc

        real_client_cls = shc.ScannerHttpClient

        def _factory(*args, **kwargs):
            kwargs["transport"] = httpx.MockTransport(handler)
            return real_client_cls(*args, **kwargs)

        return patch.object(
            __import__("src.containers.grype_adapter", fromlist=["ScannerHttpClient"]),
            "ScannerHttpClient",
            _factory,
        )

    def test_returns_matches_list(self, monkeypatch):
        import httpx

        from src.containers.grype_adapter import run_grype

        monkeypatch.setenv("SCANNER_CONTAINER_URL", "http://container:8081")

        matches = [{"vulnerability": {"id": "CVE-2024-0001"}}]

        def handler(request):
            return httpx.Response(200, json={"matches": matches})

        with self._patch_transport(handler):
            result = run_grype({"bomFormat": "CycloneDX"})

        assert result == matches

    def test_4xx_raises_failed(self, monkeypatch):
        import httpx

        from src.containers.grype_adapter import AdapterFailedError, run_grype

        monkeypatch.setenv("SCANNER_CONTAINER_URL", "http://container:8081")

        def handler(request):
            return httpx.Response(400, text="bad")

        with self._patch_transport(handler):
            with pytest.raises(AdapterFailedError):
                run_grype({"bomFormat": "CycloneDX"})

    def test_503_raises_unavailable(self, monkeypatch):
        import httpx

        from src.containers.grype_adapter import AdapterUnavailableError, run_grype

        monkeypatch.setenv("SCANNER_CONTAINER_URL", "http://container:8081")

        def handler(request):
            return httpx.Response(503, text="busy")

        with self._patch_transport(handler):
            with pytest.raises(AdapterUnavailableError):
                run_grype({"bomFormat": "CycloneDX"})

    def test_connect_error_raises_unavailable(self, monkeypatch):
        import httpx

        from src.containers.grype_adapter import AdapterUnavailableError, run_grype

        monkeypatch.setenv("SCANNER_CONTAINER_URL", "http://container:8081")

        def handler(request):
            raise httpx.ConnectError("nope")

        with self._patch_transport(handler):
            with pytest.raises(AdapterUnavailableError):
                run_grype({"bomFormat": "CycloneDX"})

    def test_env_unset_raises_unavailable(self, monkeypatch):
        from src.containers.grype_adapter import AdapterUnavailableError, run_grype

        monkeypatch.delenv("SCANNER_CONTAINER_URL", raising=False)
        with pytest.raises(AdapterUnavailableError):
            run_grype({"bomFormat": "CycloneDX"})


# ---------------------------------------------------------------------------
# code_scanning/opengrep_adapter (Phase 7: HTTP transport)
# ---------------------------------------------------------------------------

class TestOpenGrepAdapter:
    """Tests for the HTTP-transport opengrep adapter (Phase 7 Step 7).

    The adapter now POSTs ``/v1/scan`` against the warm SAST scanner; we mock
    ``ScannerHttpClient.post_json`` rather than subprocess.run. The mount
    transport keeps the test surface narrow — no boto3 fakery needed for
    the happy paths.
    """

    def test_returns_results_list(self, monkeypatch):
        from src.code_scanning import opengrep_adapter as adapter
        from src.code_scanning.opengrep_adapter import run_opengrep

        findings = [{"check_id": "python.lang.security.sqli", "path": "app.py"}]
        captured: dict = {}

        def fake_post_json(self, scanner, path, payload, timeout=None):
            captured["scanner"] = scanner
            captured["path"] = path
            captured["payload"] = payload
            return {"results": findings}

        monkeypatch.setattr(adapter, "get_checkout_transport", lambda: "mount")
        monkeypatch.setattr(
            "src.shared.scanner_http_client.ScannerHttpClient.post_json",
            fake_post_json,
        )

        result = run_opengrep(Path("/workspace/scan-1/repo-a"))

        assert result == findings
        assert captured["scanner"] == "sast"
        assert captured["path"] == "/v1/scan"
        assert captured["payload"]["checkout_ref"].startswith("workspace://")

    def test_files_arg_passed_to_payload(self, monkeypatch):
        from src.code_scanning import opengrep_adapter as adapter
        from src.code_scanning.opengrep_adapter import run_opengrep

        captured: dict = {}

        def fake_post_json(self, scanner, path, payload, timeout=None):
            captured["payload"] = payload
            return {"results": []}

        monkeypatch.setattr(adapter, "get_checkout_transport", lambda: "mount")
        monkeypatch.setattr(
            "src.shared.scanner_http_client.ScannerHttpClient.post_json",
            fake_post_json,
        )

        run_opengrep(Path("/workspace/scan-1/repo-a"), files=["src/app.py", "src/utils.py"])

        assert captured["payload"]["files"] == ["src/app.py", "src/utils.py"]

    def test_raises_unavailable_when_scanner_down(self, monkeypatch):
        from src.code_scanning.opengrep_adapter import (
            AdapterUnavailableError,
            run_opengrep,
        )

        def fake_post_json(self, scanner, path, payload, timeout=None):
            raise AdapterUnavailableError("scanner 'sast' unreachable")

        monkeypatch.setattr(
            "src.code_scanning.opengrep_adapter.get_checkout_transport",
            lambda: "mount",
        )
        monkeypatch.setattr(
            "src.shared.scanner_http_client.ScannerHttpClient.post_json",
            fake_post_json,
        )

        with pytest.raises(AdapterUnavailableError):
            run_opengrep(Path("/workspace/scan-1/repo-a"))

    def test_raises_failed_on_scanner_error(self, monkeypatch):
        from src.code_scanning.opengrep_adapter import AdapterFailedError, run_opengrep

        def fake_post_json(self, scanner, path, payload, timeout=None):
            raise AdapterFailedError("sast:/v1/scan", 500, "config error")

        monkeypatch.setattr(
            "src.code_scanning.opengrep_adapter.get_checkout_transport",
            lambda: "mount",
        )
        monkeypatch.setattr(
            "src.shared.scanner_http_client.ScannerHttpClient.post_json",
            fake_post_json,
        )

        with pytest.raises(AdapterFailedError):
            run_opengrep(Path("/workspace/scan-1/repo-a"))

    def test_empty_results_when_no_findings(self, monkeypatch):
        from src.code_scanning import opengrep_adapter as adapter
        from src.code_scanning.opengrep_adapter import run_opengrep

        monkeypatch.setattr(adapter, "get_checkout_transport", lambda: "mount")
        monkeypatch.setattr(
            "src.shared.scanner_http_client.ScannerHttpClient.post_json",
            lambda self, scanner, path, payload, timeout=None: {"results": []},
        )

        result = run_opengrep(Path("/workspace/scan-1/repo-a"))
        assert result == []


# ---------------------------------------------------------------------------
# secrets/trufflehog_adapter (Phase 7: HTTP transport)
# ---------------------------------------------------------------------------

class TestTruffleHogAdapter:
    """Tests for the HTTP-transport trufflehog adapter (Phase 7 Step 6).

    The adapter now POSTs ``/v1/scan`` against the warm secrets scanner; we
    mock ``ScannerHttpClient.post_json`` rather than subprocess.run. The
    ``mount`` transport keeps the test surface narrow — no boto3 fakery
    needed for the happy paths.
    """

    def test_returns_findings_list(self, monkeypatch):
        from src.secrets import trufflehog_adapter as adapter
        from src.secrets.trufflehog_adapter import run_trufflehog

        finding1 = {"DetectorName": "AWS", "Raw": "AKIAIOSFODNN7EXAMPLE"}
        finding2 = {"DetectorName": "GitHub", "Raw": "ghp_abc123"}
        captured: dict = {}

        def fake_post_json(self, scanner, path, payload, timeout=None):
            captured["scanner"] = scanner
            captured["path"] = path
            captured["payload"] = payload
            return {"findings": [finding1, finding2]}

        monkeypatch.setattr(adapter, "get_checkout_transport", lambda: "mount")
        monkeypatch.setattr(
            "src.shared.scanner_http_client.ScannerHttpClient.post_json",
            fake_post_json,
        )

        result = run_trufflehog(Path("/workspace/scan-1/repo-a"), "abc1234")

        assert result == [finding1, finding2]
        assert captured["scanner"] == "secrets"
        assert captured["path"] == "/v1/scan"
        assert captured["payload"]["since_commit"] == "abc1234"
        assert captured["payload"]["checkout_ref"].startswith("workspace://")

    def test_empty_findings_returns_empty_list(self, monkeypatch):
        from src.secrets import trufflehog_adapter as adapter
        from src.secrets.trufflehog_adapter import run_trufflehog

        monkeypatch.setattr(adapter, "get_checkout_transport", lambda: "mount")
        monkeypatch.setattr(
            "src.shared.scanner_http_client.ScannerHttpClient.post_json",
            lambda self, scanner, path, payload, timeout=None: {"findings": []},
        )

        result = run_trufflehog(Path("/workspace/scan-1/repo-a"), "deadbeef")
        assert result == []

    def test_raises_unavailable_when_scanner_down(self, monkeypatch):
        from src.secrets.trufflehog_adapter import (
            AdapterUnavailableError,
            run_trufflehog,
        )

        def fake_post_json(self, scanner, path, payload, timeout=None):
            raise AdapterUnavailableError("scanner 'secrets' unreachable")

        monkeypatch.setattr(
            "src.secrets.trufflehog_adapter.get_checkout_transport",
            lambda: "mount",
        )
        monkeypatch.setattr(
            "src.shared.scanner_http_client.ScannerHttpClient.post_json",
            fake_post_json,
        )

        with pytest.raises(AdapterUnavailableError):
            run_trufflehog(Path("/workspace/scan-1/repo-a"), "abc1234")

    def test_raises_failed_on_scanner_error(self, monkeypatch):
        from src.secrets.trufflehog_adapter import AdapterFailedError, run_trufflehog

        def fake_post_json(self, scanner, path, payload, timeout=None):
            raise AdapterFailedError("secrets:/v1/scan", 500, "fatal: bad object")

        monkeypatch.setattr(
            "src.secrets.trufflehog_adapter.get_checkout_transport",
            lambda: "mount",
        )
        monkeypatch.setattr(
            "src.shared.scanner_http_client.ScannerHttpClient.post_json",
            fake_post_json,
        )

        with pytest.raises(AdapterFailedError):
            run_trufflehog(Path("/workspace/scan-1/repo-a"), "badsha1")

    def test_does_not_log_raw_secret_bodies(self, monkeypatch, caplog):
        """The HTTP response carries finding ``Raw`` bodies. The adapter must
        log counts only — never the bodies themselves.
        """
        from src.secrets import trufflehog_adapter as adapter
        from src.secrets.trufflehog_adapter import run_trufflehog

        raw_secret = "AKIAIOSFODNN7EXAMPLE-very-distinct-pattern"
        finding = {"DetectorName": "AWS", "Raw": raw_secret}

        monkeypatch.setattr(adapter, "get_checkout_transport", lambda: "mount")
        monkeypatch.setattr(
            "src.shared.scanner_http_client.ScannerHttpClient.post_json",
            lambda self, scanner, path, payload, timeout=None: {"findings": [finding]},
        )

        with caplog.at_level("DEBUG"):
            result = run_trufflehog(Path("/workspace/scan-1/repo-a"), "abc1234")

        assert result == [finding]
        for record in caplog.records:
            assert raw_secret not in record.getMessage()


# ---------------------------------------------------------------------------
# secrets/baseline_delta._verify_with_trufflehog
# ---------------------------------------------------------------------------

class TestVerifyWithTrufflehog:
    """Tests for the live-verification helper that replaces the old _stub_verify."""

    def test_returns_unverified_when_binary_missing(self):
        from src.secrets.baseline_delta import _verify_with_trufflehog

        with patch("shutil.which", return_value=None):
            result = _verify_with_trufflehog("AWS", "AKIAIOSFODNN7EXAMPLE")

        assert result == "unverified"

    def test_returns_verified_when_trufflehog_finds_live_secret(self):
        from src.secrets.baseline_delta import _verify_with_trufflehog

        finding_line = json.dumps({"DetectorName": "AWS", "Verified": True, "Raw": "REDACTED"})
        cp = _make_completed(stdout=finding_line, returncode=183)

        with patch("shutil.which", return_value="/usr/local/bin/trufflehog"), \
             patch("subprocess.run", return_value=cp):
            result = _verify_with_trufflehog("AWS", "AKIAIOSFODNN7EXAMPLE")

        assert result == "verified"

    def test_returns_unverified_when_trufflehog_exits_clean(self):
        from src.secrets.baseline_delta import _verify_with_trufflehog

        cp = _make_completed(stdout="", returncode=0)

        with patch("shutil.which", return_value="/usr/local/bin/trufflehog"), \
             patch("subprocess.run", return_value=cp):
            result = _verify_with_trufflehog("GitHub", "ghp_abc123")

        assert result == "unverified"

    def test_returns_unverified_on_nonzero_exit(self):
        from src.secrets.baseline_delta import _verify_with_trufflehog

        cp = _make_completed(stdout="", returncode=1)
        cp.stderr = "fatal error"

        with patch("shutil.which", return_value="/usr/local/bin/trufflehog"), \
             patch("subprocess.run", return_value=cp):
            result = _verify_with_trufflehog("Stripe", "sk_live_abc")

        assert result == "unverified"

    def test_returns_unverified_on_timeout(self):
        from src.secrets.baseline_delta import _verify_with_trufflehog

        with patch("shutil.which", return_value="/usr/local/bin/trufflehog"), \
             patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="trufflehog", timeout=30)):
            result = _verify_with_trufflehog("Slack", "xoxb-abc123")

        assert result == "unverified"

    def test_temp_file_cleaned_up_after_run(self, tmp_path):
        """Temp file carrying the secret value must not survive the call."""
        from src.secrets.baseline_delta import _verify_with_trufflehog

        created_paths: list[str] = []
        real_ntf = tempfile.NamedTemporaryFile

        def tracking_ntf(*args, **kwargs):
            fh = real_ntf(*args, **kwargs)
            created_paths.append(fh.name)
            return fh

        cp = _make_completed(stdout="", returncode=0)

        with patch("shutil.which", return_value="/usr/local/bin/trufflehog"), \
             patch("subprocess.run", return_value=cp), \
             patch("src.secrets.baseline_delta.tempfile.NamedTemporaryFile", tracking_ntf):
            _verify_with_trufflehog("AWS", "AKIAIOSFODNN7EXAMPLE")

        for path in created_paths:
            assert not Path(path).exists(), f"temp file was not cleaned up: {path}"

    def test_unverified_finding_does_not_return_verified(self):
        from src.secrets.baseline_delta import _verify_with_trufflehog

        # Trufflehog found a finding but Verified=False (unverified by trufflehog)
        finding_line = json.dumps({"DetectorName": "GitHub", "Verified": False, "Raw": "REDACTED"})
        cp = _make_completed(stdout=finding_line, returncode=183)

        with patch("shutil.which", return_value="/usr/local/bin/trufflehog"), \
             patch("subprocess.run", return_value=cp):
            result = _verify_with_trufflehog("GitHub", "ghp_abc123")

        assert result == "unverified"


# ---------------------------------------------------------------------------
# Skip guards for real-binary integration tests (not run in CI)
# ---------------------------------------------------------------------------

@pytest.mark.skipif(shutil.which("syft") is None, reason="requires syft")
def test_real_syft_deps(tmp_path):
    from src.dependencies.syft_adapter import run_syft
    (tmp_path / "package.json").write_text('{"dependencies": {}}')
    result = run_syft(tmp_path)
    assert "components" in result


# Note: the real-binary opengrep integration test from the subprocess era was
# removed in Phase 7 — the adapter now requires a live SAST scanner container,
# which is out of scope for the in-process pytest suite. End-to-end coverage
# lives in the docker-compose-driven e2e harness.
