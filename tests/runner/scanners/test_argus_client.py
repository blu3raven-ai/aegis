"""Tests for the runner-side Argus verification client (``runner.scanners._argus``)."""
from __future__ import annotations

from pathlib import Path
from unittest import mock

import httpx
import pytest

from runner.scanners import _argus
from runner.scanners._shared import JobEnv


def _env(**vars_: str) -> JobEnv:
    return JobEnv({"envVars": dict(vars_)})


def _response(payload: dict, status: int = 200) -> mock.Mock:
    resp = mock.Mock()
    resp.json.return_value = payload
    if status >= 400:
        resp.raise_for_status.side_effect = httpx.HTTPStatusError(
            "boom", request=mock.Mock(), response=mock.Mock(status_code=status)
        )
    else:
        resp.raise_for_status.return_value = None
    return resp


# ---------------------------------------------------------------------------
# argus_configured
# ---------------------------------------------------------------------------


def test_argus_configured_true_when_endpoint_set():
    assert _argus.argus_configured(_env(ARGUS_ENDPOINT="https://argus.example")) is True


def test_argus_configured_false_when_endpoint_absent():
    assert _argus.argus_configured(_env()) is False
    assert _argus.argus_configured(_env(ARGUS_ENDPOINT="")) is False


# ---------------------------------------------------------------------------
# verify_via_argus — request building + response merge
# ---------------------------------------------------------------------------


def test_verify_builds_request_and_merges_response(tmp_path: Path):
    (tmp_path / "app.py").write_text("print('hello')\n")
    (tmp_path / "sink.py").write_text("eval(x)\n")

    findings = [
        {
            "id": "f1",
            "file_path": "app.py",
            "severity": "high",
            "code_flows": [{"file": "sink.py", "line": 1}],
        }
    ]
    env = _env(
        ARGUS_ENDPOINT="https://argus.example/",
        ARGUS_TOKEN="secret-token",
        RUN_ID="run-99",
    )
    response = _response(
        {
            "results": [
                {
                    "finding_id": "f1",
                    "verdict": "confirmed",
                    "confidence": 0.9,
                    "exploit_chain": "a -> b",
                    "evidence": ["app.py:1"],
                    "reachability": "reachable",
                    "recommended_fix": "use ast.literal_eval",
                    "rationale": "tainted",
                    "source": "argus",
                    "verification_metadata": {"model": "argus-1"},
                }
            ]
        }
    )

    with mock.patch.object(_argus.httpx, "post", return_value=response) as post:
        out = _argus.verify_via_argus(
            scanner="code_scanning",
            findings=findings,
            repo_root=str(tmp_path),
            env=env,
        )

    # Request shape
    post.assert_called_once()
    url = post.call_args.args[0] if post.call_args.args else post.call_args.kwargs["url"]
    assert url == "https://argus.example/v1/verify"
    assert post.call_args.kwargs["headers"]["Authorization"] == "Bearer secret-token"
    body = post.call_args.kwargs["json"]
    assert body["scanner"] == "code_scanning"
    assert body["scan_id"] == "run-99"
    sent = body["findings"][0]
    assert sent["finding_id"] == "f1"
    sent_files = {f["path"]: f["content"] for f in sent["code_context"]["files"]}
    assert sent_files == {"app.py": "print('hello')\n", "sink.py": "eval(x)\n"}

    # Response merge
    merged = out[0]
    assert merged["verdict"] == "confirmed"
    assert merged["evidence"] == ["app.py:1"]
    assert merged["exploit_chain"] == "a -> b"
    assert merged["verification_metadata"] == {"model": "argus-1"}
    assert merged["recommended_fix"] == "use ast.literal_eval"
    assert merged["reachability"] == "reachable"


def test_verify_falls_back_to_index_when_no_id(tmp_path: Path):
    findings = [{"file_path": "missing.py"}]
    env = _env(ARGUS_ENDPOINT="https://argus.example", ARGUS_TOKEN="t")
    response = _response({"results": [{"finding_id": "0", "verdict": "rejected"}]})

    with mock.patch.object(_argus.httpx, "post", return_value=response) as post:
        out = _argus.verify_via_argus(
            scanner="secrets", findings=findings, repo_root=str(tmp_path), env=env
        )

    assert post.call_args.kwargs["json"]["findings"][0]["finding_id"] == "0"
    assert out[0]["verdict"] == "rejected"


# ---------------------------------------------------------------------------
# repo-jail
# ---------------------------------------------------------------------------


def test_verify_repo_jail_rejects_path_escape(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "ok.py").write_text("ok\n")
    # A secret outside the repo that a malicious finding tries to exfiltrate.
    (tmp_path / "passwd").write_text("root:x:0:0\n")

    findings = [{"id": "x", "file_path": "../passwd"}]
    env = _env(ARGUS_ENDPOINT="https://argus.example", ARGUS_TOKEN="t")
    response = _response({"results": [{"finding_id": "x", "verdict": "rejected"}]})

    with mock.patch.object(_argus.httpx, "post", return_value=response) as post:
        _argus.verify_via_argus(
            scanner="code_scanning", findings=findings, repo_root=str(repo), env=env
        )

    files = post.call_args.kwargs["json"]["findings"][0]["code_context"]["files"]
    assert files == []  # escape path never read


def test_verify_skips_oversize_file(tmp_path: Path):
    big = tmp_path / "big.py"
    big.write_text("x" * (_argus._MAX_CONTEXT_FILE_BYTES + 1))
    findings = [{"id": "x", "file_path": "big.py"}]
    env = _env(ARGUS_ENDPOINT="https://argus.example", ARGUS_TOKEN="t")
    response = _response({"results": [{"finding_id": "x", "verdict": "rejected"}]})

    with mock.patch.object(_argus.httpx, "post", return_value=response) as post:
        _argus.verify_via_argus(
            scanner="code_scanning", findings=findings, repo_root=str(tmp_path), env=env
        )

    assert post.call_args.kwargs["json"]["findings"][0]["code_context"]["files"] == []


# ---------------------------------------------------------------------------
# fail-open
# ---------------------------------------------------------------------------


def test_verify_fail_open_on_transport_error(tmp_path: Path):
    findings = [{"id": "a", "file_path": "x.py"}, {"id": "b"}]
    env = _env(ARGUS_ENDPOINT="https://argus.example", ARGUS_TOKEN="t")

    with mock.patch.object(
        _argus.httpx, "post", side_effect=httpx.ConnectError("down")
    ):
        out = _argus.verify_via_argus(
            scanner="secrets", findings=findings, repo_root=str(tmp_path), env=env
        )

    assert [f["verdict"] for f in out] == [None, None]
    for f in out:
        assert f["verification_metadata"]["skipped"] == "argus_error:ConnectError"


def test_verify_fail_open_on_non_200(tmp_path: Path):
    findings = [{"id": "a"}]
    env = _env(ARGUS_ENDPOINT="https://argus.example", ARGUS_TOKEN="t")
    response = _response({}, status=500)

    with mock.patch.object(_argus.httpx, "post", return_value=response):
        out = _argus.verify_via_argus(
            scanner="secrets", findings=findings, repo_root=str(tmp_path), env=env
        )

    assert out[0]["verdict"] is None
    assert out[0]["verification_metadata"]["skipped"] == "argus_error:HTTPStatusError"


def test_verify_fail_open_on_malformed_response(tmp_path: Path):
    findings = [{"id": "a"}]
    env = _env(ARGUS_ENDPOINT="https://argus.example", ARGUS_TOKEN="t")
    response = _response({"unexpected": True})

    with mock.patch.object(_argus.httpx, "post", return_value=response):
        out = _argus.verify_via_argus(
            scanner="secrets", findings=findings, repo_root=str(tmp_path), env=env
        )

    assert out[0]["verdict"] is None
    assert out[0]["verification_metadata"]["skipped"] == "argus_error:ValueError"


def test_verify_empty_findings_short_circuits(tmp_path: Path):
    env = _env(ARGUS_ENDPOINT="https://argus.example", ARGUS_TOKEN="t")
    with mock.patch.object(_argus.httpx, "post") as post:
        out = _argus.verify_via_argus(
            scanner="secrets", findings=[], repo_root=str(tmp_path), env=env
        )
    assert out == []
    post.assert_not_called()


# ---------------------------------------------------------------------------
# correlate_via_argus — request building + response passthrough
# ---------------------------------------------------------------------------


def test_correlate_returns_server_findings_verbatim(tmp_path: Path):
    findings = [{"id": "f1", "repository": "acme-org/widget"}]
    env = _env(ARGUS_ENDPOINT="https://argus.example/", ARGUS_TOKEN="secret-token")
    server_findings = [
        {
            "correlation_id": "corr-0001",
            "verdict": "chain_confirmed",
            "chain_severity": "high",
            "chain_description": "chain",
            "source_finding_ids": ["f1"],
        }
    ]
    response = _response({"correlated_findings": server_findings})

    with mock.patch.object(_argus.httpx, "post", return_value=response) as post:
        out = _argus.correlate_via_argus(
            findings=findings, repo_root_for={}, env=env, budget=4000
        )

    url = post.call_args.args[0] if post.call_args.args else post.call_args.kwargs["url"]
    assert url == "https://argus.example/v1/correlate"
    assert post.call_args.kwargs["headers"]["Authorization"] == "Bearer secret-token"
    assert post.call_args.kwargs["json"]["budget"] == 4000
    assert out == server_findings


def test_correlate_ships_code_context_from_resolved_root(tmp_path: Path):
    repo_root = tmp_path / "checkout"
    repo_root.mkdir()
    (repo_root / "api.py").write_text("def handler(): ...\n")

    findings = [{"id": "f1", "repository": "acme-org/widget", "file_path": "api.py"}]
    env = _env(ARGUS_ENDPOINT="https://argus.example", ARGUS_TOKEN="t")
    response = _response({"correlated_findings": []})

    with mock.patch.object(_argus.httpx, "post", return_value=response) as post:
        _argus.correlate_via_argus(
            findings=findings,
            repo_root_for={"acme-org/widget": repo_root},
            env=env,
            budget=100,
        )

    sent = post.call_args.kwargs["json"]["findings"][0]
    assert sent["detail"] == findings[0]
    files = {f["path"]: f["content"] for f in sent["code_context"]["files"]}
    assert files == {"api.py": "def handler(): ...\n"}


def test_correlate_ships_empty_files_when_repo_unmapped(tmp_path: Path):
    findings = [{"id": "f1", "repository": "acme-org/unknown", "file_path": "api.py"}]
    env = _env(ARGUS_ENDPOINT="https://argus.example", ARGUS_TOKEN="t")
    response = _response({"correlated_findings": []})

    with mock.patch.object(_argus.httpx, "post", return_value=response) as post:
        _argus.correlate_via_argus(
            findings=findings, repo_root_for={}, env=env, budget=100
        )

    assert post.call_args.kwargs["json"]["findings"][0]["code_context"]["files"] == []


def test_correlate_fail_open_on_transport_error(tmp_path: Path):
    findings = [{"id": "f1", "repository": "r"}]
    env = _env(ARGUS_ENDPOINT="https://argus.example", ARGUS_TOKEN="t")

    with mock.patch.object(_argus.httpx, "post", side_effect=httpx.ConnectError("down")):
        out = _argus.correlate_via_argus(
            findings=findings, repo_root_for={}, env=env, budget=100
        )

    assert out == []


def test_correlate_fail_open_on_non_200(tmp_path: Path):
    findings = [{"id": "f1", "repository": "r"}]
    env = _env(ARGUS_ENDPOINT="https://argus.example", ARGUS_TOKEN="t")
    response = _response({}, status=500)

    with mock.patch.object(_argus.httpx, "post", return_value=response):
        out = _argus.correlate_via_argus(
            findings=findings, repo_root_for={}, env=env, budget=100
        )

    assert out == []


def test_correlate_fail_open_on_malformed_response(tmp_path: Path):
    findings = [{"id": "f1", "repository": "r"}]
    env = _env(ARGUS_ENDPOINT="https://argus.example", ARGUS_TOKEN="t")
    response = _response({"correlated_findings": "not-a-list"})

    with mock.patch.object(_argus.httpx, "post", return_value=response):
        out = _argus.correlate_via_argus(
            findings=findings, repo_root_for={}, env=env, budget=100
        )

    assert out == []


def test_correlate_empty_findings_short_circuits(tmp_path: Path):
    env = _env(ARGUS_ENDPOINT="https://argus.example", ARGUS_TOKEN="t")
    with mock.patch.object(_argus.httpx, "post") as post:
        out = _argus.correlate_via_argus(
            findings=[], repo_root_for={}, env=env, budget=100
        )
    assert out == []
    post.assert_not_called()


# ---------------------------------------------------------------------------
# _finding_paths
# ---------------------------------------------------------------------------


def test_finding_paths_extracts_trufflehog_nested_path():
    finding = {
        "id": "s1",
        "SourceMetadata": {"Data": {"Filesystem": {"file": "/out/repo/_checkout/.env"}}},
    }
    assert _argus._finding_paths(finding) == ["/out/repo/_checkout/.env"]


def test_finding_paths_prefers_top_level_over_trufflehog():
    finding = {
        "id": "s1",
        "file_path": "app.py",
        "SourceMetadata": {"Data": {"Filesystem": {"file": "/out/repo/_checkout/.env"}}},
    }
    assert _argus._finding_paths(finding) == ["app.py"]


# ---------------------------------------------------------------------------
# _resolve_inside_root
# ---------------------------------------------------------------------------


def test_resolve_inside_root_accepts_absolute_inside_root(tmp_path: Path):
    target = tmp_path / "_checkout" / "x.env"
    target.parent.mkdir(parents=True)
    target.write_text("KEY=val\n")
    resolved = _argus._resolve_inside_root(tmp_path, str(target))
    assert resolved == target.resolve()


def test_resolve_inside_root_rejects_absolute_outside_root(tmp_path: Path):
    root = tmp_path / "repo"
    root.mkdir()
    outside = tmp_path / "passwd"
    outside.write_text("root:x:0:0\n")
    assert _argus._resolve_inside_root(root, str(outside)) is None


def test_resolve_inside_root_accepts_relative_path(tmp_path: Path):
    (tmp_path / "app.py").write_text("ok\n")
    resolved = _argus._resolve_inside_root(tmp_path, "app.py")
    assert resolved == (tmp_path / "app.py").resolve()


def test_resolve_inside_root_rejects_dotdot_escape(tmp_path: Path):
    root = tmp_path / "repo"
    root.mkdir()
    assert _argus._resolve_inside_root(root, "../passwd") is None


def test_verify_sends_context_for_absolute_secret_path(tmp_path: Path):
    secret_file = tmp_path / "_checkout" / "x.env"
    secret_file.parent.mkdir(parents=True)
    secret_file.write_text("AWS_SECRET=AKIAEXAMPLE\n")

    findings = [
        {
            "id": "s1",
            "SourceMetadata": {"Data": {"Filesystem": {"file": str(secret_file)}}},
        }
    ]
    env = _env(ARGUS_ENDPOINT="https://argus.example", ARGUS_TOKEN="t", RUN_ID="run-1")
    response = _response({"results": [{"finding_id": "s1", "verdict": "confirmed"}]})

    with mock.patch.object(_argus.httpx, "post", return_value=response) as post:
        out = _argus.verify_via_argus(
            scanner="secrets", findings=findings, repo_root=str(tmp_path), env=env
        )

    files = post.call_args.kwargs["json"]["findings"][0]["code_context"]["files"]
    sent = {f["path"]: f["content"] for f in files}
    assert sent == {str(secret_file): "AWS_SECRET=AKIAEXAMPLE\n"}
    assert out[0]["verdict"] == "confirmed"


# ---------------------------------------------------------------------------
# seam routing — code_scanning + secrets _verify_findings_file
# ---------------------------------------------------------------------------


def test_code_scanning_seam_routes_to_argus_when_configured(tmp_path: Path):
    from runner.scanners.code_scanning import scanner as cs

    findings_file = tmp_path / "findings.jsonl"
    findings_file.write_text('{"id":"f1","file_path":"a.py","severity":"high"}\n')
    env = _env(ARGUS_ENDPOINT="https://argus.example", ARGUS_TOKEN="t")

    with mock.patch.object(
        cs, "verify_via_argus", return_value=[{"id": "f1", "verdict": "confirmed"}]
    ) as via_argus, mock.patch.object(cs, "_maybe_verify") as local:
        cs.CodeScanningScanner()._verify_findings_file(
            findings_file, repo_root=str(tmp_path), env=env
        )

    via_argus.assert_called_once()
    assert via_argus.call_args.kwargs["scanner"] == "code_scanning"
    local.assert_not_called()
    assert '"verdict":"confirmed"' in findings_file.read_text()


def test_code_scanning_seam_uses_local_when_unconfigured(tmp_path: Path):
    from runner.scanners.code_scanning import scanner as cs

    findings_file = tmp_path / "findings.jsonl"
    findings_file.write_text('{"id":"f1","file_path":"a.py","severity":"high"}\n')
    env = _env()  # no ARGUS_ENDPOINT

    with mock.patch.object(cs, "verify_via_argus") as via_argus, mock.patch.object(
        cs, "_maybe_verify", return_value=[{"id": "f1", "verdict": None}]
    ) as local:
        cs.CodeScanningScanner()._verify_findings_file(
            findings_file, repo_root=str(tmp_path), env=env
        )

    via_argus.assert_not_called()
    local.assert_called_once()


def test_secrets_seam_routes_to_argus_when_configured(tmp_path: Path):
    from runner.scanners.secrets import scanner as ss

    findings_file = tmp_path / "findings.jsonl"
    findings_file.write_text('{"id":"s1","file":"a.py"}\n')
    env = _env(ARGUS_ENDPOINT="https://argus.example", ARGUS_TOKEN="t")

    with mock.patch.object(
        ss, "verify_via_argus", return_value=[{"id": "s1", "verdict": "confirmed"}]
    ) as via_argus, mock.patch.object(ss, "_maybe_verify_secrets") as local:
        ss.SecretsScanner()._verify_findings_file(
            findings_file, repo_root=str(tmp_path), env=env
        )

    via_argus.assert_called_once()
    assert via_argus.call_args.kwargs["scanner"] == "secrets"
    local.assert_not_called()


def test_secrets_seam_uses_local_when_unconfigured(tmp_path: Path):
    from runner.scanners.secrets import scanner as ss

    findings_file = tmp_path / "findings.jsonl"
    findings_file.write_text('{"id":"s1","file":"a.py"}\n')
    env = _env()

    with mock.patch.object(ss, "verify_via_argus") as via_argus, mock.patch.object(
        ss, "_maybe_verify_secrets", return_value=[{"id": "s1", "verdict": None}]
    ) as local:
        ss.SecretsScanner()._verify_findings_file(
            findings_file, repo_root=str(tmp_path), env=env
        )

    via_argus.assert_not_called()
    local.assert_called_once()


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
