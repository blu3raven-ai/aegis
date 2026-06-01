"""Tests for AegisClient — mock httpx responses, verify request shapes."""

from __future__ import annotations

import json

import httpx
import pytest

from aegis_cli.client import AegisClient, AegisAPIError, SCANNER_ENDPOINT_MAP


BASE_URL = "https://aegis.example.org"
TOKEN = "test-token-xyz"


def _make_client() -> AegisClient:
    return AegisClient(base_url=BASE_URL, api_token=TOKEN, timeout=5.0)


def _mock_transport(responses: dict[str, tuple[int, dict]]):
    """Return an httpx transport that serves canned responses by URL path."""

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        for pattern, (status, body) in responses.items():
            if pattern in path:
                return httpx.Response(status, json=body)
        return httpx.Response(404, json={"detail": "not found"})

    return httpx.MockTransport(handler)


class MockTransport(httpx.BaseTransport):
    def __init__(self, responses: dict[str, tuple[int, dict]]):
        self._responses = responses

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        for pattern, (status, body) in self._responses.items():
            if pattern in path:
                return httpx.Response(status, json=body)
        return httpx.Response(404, json={"detail": "not found"})


def _client_with_mock(responses: dict[str, tuple[int, dict]]) -> AegisClient:
    client = AegisClient(base_url=BASE_URL, api_token=TOKEN, timeout=5.0)
    client._http = httpx.Client(
        transport=MockTransport(responses),
        headers={"Authorization": f"Bearer {TOKEN}"},
    )
    return client


# ---------------------------------------------------------------------------
# Auth header
# ---------------------------------------------------------------------------


def test_bearer_token_sent():
    sent_headers: list[dict] = []

    class CapturingTransport(httpx.BaseTransport):
        def handle_request(self, request: httpx.Request) -> httpx.Response:
            sent_headers.append(dict(request.headers))
            return httpx.Response(202, json={"runs": [], "message": "ok"})

    client = AegisClient(base_url=BASE_URL, api_token=TOKEN)
    client._http = httpx.Client(
        transport=CapturingTransport(),
        headers={"Authorization": f"Bearer {TOKEN}"},
    )
    client.trigger_scan(org="example-org")
    assert sent_headers[0].get("authorization") == f"Bearer {TOKEN}"


# ---------------------------------------------------------------------------
# trigger_scan
# ---------------------------------------------------------------------------


def test_trigger_scan_posts_to_dependencies():
    client = _client_with_mock({
        "/dependencies/api/runs": (202, {"runs": [{"org": "example-org", "queued": True}], "message": "Started"}),
    })
    result = client.trigger_scan(org="example-org", scanner_type="dependencies")
    assert result["runs"][0]["org"] == "example-org"


def test_trigger_scan_posts_to_code_scanning():
    client = _client_with_mock({
        "/code-scanning/api/runs": (202, {"runs": [{"org": "example-org", "queued": True}], "message": "ok"}),
    })
    result = client.trigger_scan(org="example-org", scanner_type="code_scanning")
    assert "runs" in result


def test_trigger_scan_unknown_scanner_raises():
    client = _make_client()
    with pytest.raises(AegisAPIError, match="Unknown scanner type"):
        client.trigger_scan(org="example-org", scanner_type="nonexistent")


def test_trigger_scan_http_error_raises():
    client = _client_with_mock({
        "/dependencies/api/runs": (409, {"error": "scan already running"}),
    })
    with pytest.raises(AegisAPIError) as exc_info:
        client.trigger_scan(org="example-org")
    assert exc_info.value.status_code == 409


# ---------------------------------------------------------------------------
# get_scan_status
# ---------------------------------------------------------------------------


def test_get_scan_status_finds_matching_run():
    client = _client_with_mock({
        "/dependencies/api/history": (200, {
            "history": [
                {"id": "run-abc", "org": "example-org", "status": "completed", "findingsCount": 5},
            ],
        }),
    })
    run = client.get_scan_status("run-abc", org="example-org")
    assert run["id"] == "run-abc"
    assert run["status"] == "completed"


def test_get_scan_status_not_found_raises_404():
    client = _client_with_mock({
        "/dependencies/api/history": (200, {"history": []}),
        "/code-scanning/api/history": (200, {"history": []}),
        "/secrets/api/history": (200, {"history": []}),
        "/container-scanning/api/history": (200, {"history": []}),
    })
    with pytest.raises(AegisAPIError) as exc_info:
        client.get_scan_status("nonexistent-id", org="example-org")
    assert exc_info.value.status_code == 404


# ---------------------------------------------------------------------------
# get_findings
# ---------------------------------------------------------------------------


def test_get_findings_returns_empty_on_no_data():
    client = _client_with_mock({
        "/dependencies/api/history": (200, {"history": []}),
        "/code-scanning/api/history": (200, {"history": []}),
        "/secrets/api/history": (200, {"history": []}),
        "/container-scanning/api/history": (200, {"history": []}),
    })
    findings = client.get_findings(org="example-org")
    assert findings == []


def test_get_findings_filters_by_severity():
    alert_crit = {
        "state": "open",
        "security_advisory": {"severity": "critical", "ghsa_id": "GHSA-x"},
    }
    alert_low = {
        "state": "open",
        "security_advisory": {"severity": "low", "ghsa_id": "GHSA-y"},
    }
    client = _client_with_mock({
        "/dependencies/api/history": (200, {
            "history": [
                {"id": "r1", "status": "completed", "alerts": [alert_crit, alert_low]},
            ],
        }),
    })
    findings = client.get_findings(
        org="example-org", severity=["critical"], scanner=["dependencies"]
    )
    assert len(findings) == 1
    assert findings[0]["security_advisory"]["severity"] == "critical"


def test_get_findings_filters_by_repo():
    alert_match = {
        "state": "open",
        "repository": {"full_name": "example-org/api-service"},
        "security_advisory": {"severity": "high"},
    }
    alert_other = {
        "state": "open",
        "repository": {"full_name": "example-org/other-service"},
        "security_advisory": {"severity": "high"},
    }
    client = _client_with_mock({
        "/dependencies/api/history": (200, {
            "history": [
                {"id": "r1", "status": "completed", "alerts": [alert_match, alert_other]},
            ],
        }),
    })
    findings = client.get_findings(
        org="example-org", repo="api-service", scanner=["dependencies"]
    )
    assert len(findings) == 1
    assert "api-service" in findings[0]["repository"]["full_name"]


# ---------------------------------------------------------------------------
# list_findings — aggregated GET /api/v1/findings
# ---------------------------------------------------------------------------


def test_list_findings_calls_aggregated_endpoint():
    envelope = {
        "findings": [
            {"id": "f1", "scanner": "deps", "severity": "high", "repo": "example-org/svc"},
        ],
        "next_cursor": None,
        "total_count": 1,
    }
    client = _client_with_mock({"/api/v1/findings": (200, envelope)})
    result = client.list_findings(org="example-org")
    assert result["findings"][0]["id"] == "f1"
    assert result["total_count"] == 1
    assert result["next_cursor"] is None


def test_list_findings_forwards_query_params():
    captured: dict = {}

    class CapturingTransport(httpx.BaseTransport):
        def handle_request(self, request: httpx.Request) -> httpx.Response:
            captured["params"] = dict(request.url.params)
            return httpx.Response(200, json={"findings": [], "next_cursor": None, "total_count": 0})

    client = AegisClient(base_url=BASE_URL, api_token=TOKEN)
    client._http = httpx.Client(
        transport=CapturingTransport(),
        headers={"Authorization": f"Bearer {TOKEN}"},
    )
    client.list_findings(
        org="example-org",
        severity=["critical", "high"],
        scanner=["dependencies", "secrets"],
        state=["open"],
        q="log4j",
        cve="CVE-2021-44228",
        sort="created_at",
        direction="asc",
        limit=25,
        cursor="abc",
    )
    p = captured["params"]
    assert p["org_id"] == "example-org"
    assert p["severity"] == "critical,high"
    # dependencies -> deps, secrets -> secrets
    assert p["scanner"] == "deps,secrets"
    assert p["state"] == "open"
    assert p["q"] == "log4j"
    assert p["cve"] == "CVE-2021-44228"
    assert p["sort"] == "created_at"
    assert p["direction"] == "asc"
    assert p["limit"] == "25"
    assert p["cursor"] == "abc"


def test_list_findings_translates_scanner_aliases():
    captured: dict = {}

    class CapturingTransport(httpx.BaseTransport):
        def handle_request(self, request: httpx.Request) -> httpx.Response:
            captured["params"] = dict(request.url.params)
            return httpx.Response(200, json={"findings": [], "next_cursor": None, "total_count": 0})

    client = AegisClient(base_url=BASE_URL, api_token=TOKEN)
    client._http = httpx.Client(
        transport=CapturingTransport(),
        headers={"Authorization": f"Bearer {TOKEN}"},
    )
    client.list_findings(
        org="example-org",
        scanner=["code_scanning", "containers", "container_scanning"],
    )
    # All three aliases collapse to the endpoint's public shorthand.
    assert captured["params"]["scanner"] == "sast,container,container"


def test_list_findings_propagates_http_errors():
    client = _client_with_mock({"/api/v1/findings": (400, {"detail": "invalid severity"})})
    with pytest.raises(AegisAPIError) as exc_info:
        client.list_findings(org="example-org", severity=["nonexistent"])
    assert exc_info.value.status_code == 400


# ---------------------------------------------------------------------------
# iter_all_findings — cursor walker
# ---------------------------------------------------------------------------


def test_iter_all_findings_walks_cursor():
    pages = [
        {
            "findings": [{"id": "a"}, {"id": "b"}],
            "next_cursor": "page-2",
            "total_count": 3,
        },
        {
            "findings": [{"id": "c"}],
            "next_cursor": None,
            "total_count": 3,
        },
    ]
    captured: list[dict] = []

    class CursorTransport(httpx.BaseTransport):
        def handle_request(self, request: httpx.Request) -> httpx.Response:
            captured.append(dict(request.url.params))
            return httpx.Response(200, json=pages[len(captured) - 1])

    client = AegisClient(base_url=BASE_URL, api_token=TOKEN)
    client._http = httpx.Client(
        transport=CursorTransport(),
        headers={"Authorization": f"Bearer {TOKEN}"},
    )
    result = client.iter_all_findings(org="example-org", severity=["critical"])
    assert [f["id"] for f in result] == ["a", "b", "c"]
    assert len(captured) == 2
    assert "cursor" not in captured[0]
    assert captured[1]["cursor"] == "page-2"
    assert captured[1]["severity"] == "critical"


def test_iter_all_findings_respects_max_bound():
    """Defensive ceiling halts iteration even when the server keeps returning cursors."""
    call_count = {"n": 0}

    class RunawayCursorTransport(httpx.BaseTransport):
        def handle_request(self, request: httpx.Request) -> httpx.Response:
            call_count["n"] += 1
            return httpx.Response(
                200,
                json={
                    "findings": [{"id": f"f-{call_count['n']}-1"}, {"id": f"f-{call_count['n']}-2"}],
                    "next_cursor": f"cursor-{call_count['n']}",
                    "total_count": None,
                },
            )

    client = AegisClient(base_url=BASE_URL, api_token=TOKEN)
    client._http = httpx.Client(
        transport=RunawayCursorTransport(),
        headers={"Authorization": f"Bearer {TOKEN}"},
    )
    result = client.iter_all_findings(org="example-org", max_findings=5)
    # Loop stops once collected count crosses the ceiling, then result is sliced.
    assert len(result) == 5
    # 3 calls return 2 findings each (6 collected); the 3rd page trips the bound.
    assert call_count["n"] == 3


# ---------------------------------------------------------------------------
# get_decision
# ---------------------------------------------------------------------------


def test_get_decision_uses_backend_when_available():
    decision_payload = {
        "decision": "allow",
        "blockers": [],
        "rationale": "No critical findings.",
        "source": "backend",
    }
    client = _client_with_mock({
        "/api/v1/decisions/go-no-go": (200, decision_payload),
    })
    result = client.get_decision(org="example-org", repo="example-org/svc")
    assert result["decision"] == "allow"
    assert result["source"] == "backend"


def test_get_decision_posts_org_id_and_repo_in_body():
    """The CLI hits the endpoint with POST and an {org_id, repo, policy} body."""
    captured: dict = {}

    class CapturingTransport(httpx.BaseTransport):
        def handle_request(self, request: httpx.Request) -> httpx.Response:
            captured["method"] = request.method
            captured["path"] = request.url.path
            try:
                captured["body"] = json.loads(request.content)
            except Exception:
                captured["body"] = None
            return httpx.Response(
                200,
                json={
                    "decision": "allow",
                    "blockers": [],
                    "rationale": "ok",
                    "source": "backend",
                },
            )

    client = AegisClient(base_url=BASE_URL, api_token=TOKEN)
    client._http = httpx.Client(
        transport=CapturingTransport(),
        headers={"Authorization": f"Bearer {TOKEN}"},
    )
    client.get_decision(
        org="example-org",
        repo="example-org/svc",
        block_on=["critical", "high"],
    )
    assert captured["method"] == "POST"
    assert captured["path"] == "/api/v1/decisions/go-no-go"
    assert captured["body"]["org_id"] == "example-org"
    assert captured["body"]["repo"] == "example-org/svc"
    assert captured["body"]["policy"]["block_on"] == ["critical", "high"]


def test_get_decision_strips_service_id_from_policy():
    """service_id is accepted as a kwarg but must not leak onto the wire."""
    captured: dict = {}

    class CapturingTransport(httpx.BaseTransport):
        def handle_request(self, request: httpx.Request) -> httpx.Response:
            try:
                captured["body"] = json.loads(request.content)
            except Exception:
                captured["body"] = None
            return httpx.Response(
                200,
                json={
                    "decision": "allow",
                    "blockers": [],
                    "rationale": "ok",
                    "source": "backend",
                },
            )

    client = AegisClient(base_url=BASE_URL, api_token=TOKEN)
    client._http = httpx.Client(
        transport=CapturingTransport(),
        headers={"Authorization": f"Bearer {TOKEN}"},
    )
    client.get_decision(
        org="example-org",
        repo="example-org/svc",
        service_id="svc-123",
        block_on=["critical"],
    )
    body = captured["body"]
    assert "service_id" not in body
    assert "service_id" not in body.get("policy", {})


def test_get_decision_local_heuristic_on_404():
    """When the decision endpoint returns 404, fall back to heuristic."""
    client = _client_with_mock({
        "/api/v1/decisions/go-no-go": (404, {"detail": "not found"}),
        "/dependencies/api/history": (200, {"history": []}),
        "/code-scanning/api/history": (200, {"history": []}),
        "/secrets/api/history": (200, {"history": []}),
        "/container-scanning/api/history": (200, {"history": []}),
    })
    result = client.get_decision(
        org="example-org", repo="example-org/svc", block_on=["critical"]
    )
    assert result["decision"] == "allow"
    assert result["source"] == "local"


def test_get_decision_blocks_on_critical_finding():
    crit_alert = {
        "state": "open",
        "repository": {"full_name": "example-org/svc"},
        "security_advisory": {"severity": "critical", "ghsa_id": "GHSA-z"},
    }
    client = _client_with_mock({
        "/api/v1/decisions/go-no-go": (404, {"detail": "not found"}),
        "/dependencies/api/history": (200, {
            "history": [
                {"id": "r1", "status": "completed", "alerts": [crit_alert]},
            ],
        }),
        "/code-scanning/api/history": (200, {"history": []}),
        "/secrets/api/history": (200, {"history": []}),
        "/container-scanning/api/history": (200, {"history": []}),
    })
    result = client.get_decision(
        org="example-org", repo="example-org/svc", block_on=["critical"]
    )
    assert result["decision"] == "block"
    assert len(result["blockers"]) == 1
    assert result["source"] == "local"


def test_get_decision_500_bubbles_up_no_local_fallback():
    """Backend 5xx must surface as AegisAPIError, not silently degrade."""
    client = _client_with_mock({
        "/api/v1/decisions/go-no-go": (500, {"detail": "internal error"}),
    })
    with pytest.raises(AegisAPIError) as exc_info:
        client.get_decision(
            org="example-org", repo="example-org/svc", block_on=["critical"]
        )
    assert exc_info.value.status_code == 500


# ---------------------------------------------------------------------------
# Error handling
# ---------------------------------------------------------------------------


def test_invalid_json_response_raises():
    class BadTransport(httpx.BaseTransport):
        def handle_request(self, request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, content=b"not-json")

    client = AegisClient(base_url=BASE_URL, api_token=TOKEN)
    client._http = httpx.Client(transport=BadTransport(), headers={})
    with pytest.raises(AegisAPIError, match="Invalid JSON"):
        client.trigger_scan(org="example-org")
