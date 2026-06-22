"""Smoke tests for /api/v1/scans/manual and /api/v1/scans/{scan_id}."""
from __future__ import annotations

import os
from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch

from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost:5432/test")
os.environ.setdefault("RUNNER_ENCRYPTION_KEY", "0" * 64)

from src.authz.enforcement.dependencies import Permission  # noqa: E402
from src.authz.permissions.catalog import RUN_SCANS, VIEW_FINDINGS  # noqa: E402
from src.scans.manual_router import router as scans_manual_router  # noqa: E402
from src.scans.router import router as scans_router  # noqa: E402
from src.scans.service import ScanDetail, ScanSubmission  # noqa: E402

_WRITER_PERMS = {"view_findings", "run_scans"}
_VIEWER_PERMS = {"view_findings"}

_FAKE_ASSET_ID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"


def _make_app(
    *,
    allow_view_findings: bool = True,
    allow_run_scans: bool = True,
) -> FastAPI:
    app = FastAPI()
    app.include_router(scans_manual_router)
    app.include_router(scans_router)

    @app.middleware("http")
    async def inject_user(request: Request, call_next):
        request.state.user_sub = "admin-user"
        request.state.user_role = "admin"
        request.state.user_role_id = None
        request.state.user_org = "test-org"
        return await call_next(request)

    if allow_view_findings:
        # The Permission(VIEW_FINDINGS) declarative gate on /scans/{scan_id}
        # hits has_role_permission → run_db, which has no DB in unit tests.
        # Override the dep for happy/scope-mocked paths; the rejection test
        # uses allow_view_findings=False to exercise the real gate.
        app.dependency_overrides[Permission(VIEW_FINDINGS)] = lambda: None
    if allow_run_scans:
        app.dependency_overrides[Permission(RUN_SCANS)] = lambda: None
    return app


def _fake_submission() -> ScanSubmission:
    return ScanSubmission(
        scan_id="scan-abc",
        repo_id="acme-org/repo-1",
        commit_sha="a" * 40,
        scanner_types=["dependencies_scanning"],
        status="queued",
        submitted_at=datetime(2026, 6, 4, tzinfo=timezone.utc),
        submitted_by="admin-user",
    )


def _fake_detail() -> ScanDetail:
    return ScanDetail(
        scan_id="scan-abc",
        repo_id="acme-org/repo-1",
        commit_sha="a" * 40,
        scanner_types=["dependencies_scanning"],
        status="completed",
        submitted_at=datetime(2026, 6, 4, tzinfo=timezone.utc),
        submitted_by="admin-user",
        started_at=datetime(2026, 6, 4, 0, 1, tzinfo=timezone.utc),
        finished_at=datetime(2026, 6, 4, 0, 5, tzinfo=timezone.utc),
        finding_counts={"critical": 0, "high": 1, "medium": 2, "low": 0},
        error=None,
    )


def test_submit_scan_happy_path():
    with patch("src.authz.enforcement._resolve_effective_permissions", return_value=_WRITER_PERMS), \
         patch("src.scans.manual_router.resolve_asset_ids_from_request", new=AsyncMock(return_value=[_FAKE_ASSET_ID])), \
         patch("src.scans.manual_router.submit_scan", new=AsyncMock(return_value=_fake_submission())):
        client = TestClient(_make_app())
        resp = client.post(
            "/api/v1/scans/manual",
            json={"asset_id": _FAKE_ASSET_ID, "commit_sha": "a" * 40, "scanner_types": ["dependencies_scanning"]},
        )
        assert resp.status_code == 202, resp.text
        body = resp.json()
        assert body["scan_id"] == "scan-abc"
        assert body["status"] == "queued"
        assert body["submitted_at"]  # ISO string present


def test_submit_scan_invalid_sha():
    with patch("src.authz.enforcement._resolve_effective_permissions", return_value=_WRITER_PERMS):
        client = TestClient(_make_app())
        resp = client.post(
            "/api/v1/scans/manual",
            json={"asset_id": _FAKE_ASSET_ID, "commit_sha": "nope"},
        )
        assert resp.status_code == 422


def test_submit_scan_unknown_scanner_type():
    with patch("src.authz.enforcement._resolve_effective_permissions", return_value=_WRITER_PERMS):
        client = TestClient(_make_app())
        resp = client.post(
            "/api/v1/scans/manual",
            json={"asset_id": _FAKE_ASSET_ID, "commit_sha": "a" * 40, "scanner_types": ["bogus"]},
        )
        assert resp.status_code == 422


def test_submit_scan_repo_not_found():
    with patch("src.authz.enforcement._resolve_effective_permissions", return_value=_WRITER_PERMS), \
         patch("src.scans.manual_router.resolve_asset_ids_from_request", new=AsyncMock(return_value=[_FAKE_ASSET_ID])), \
         patch("src.scans.manual_router.submit_scan", new=AsyncMock(return_value=None)):
        client = TestClient(_make_app())
        resp = client.post(
            "/api/v1/scans/manual",
            json={"asset_id": _FAKE_ASSET_ID, "commit_sha": "a" * 40},
        )
        assert resp.status_code == 404


def test_submit_scan_missing_permission():
    with patch("src.authz.enforcement.dependencies.has_role_permission", return_value=False):
        client = TestClient(_make_app(allow_run_scans=False))
        resp = client.post(
            "/api/v1/scans/manual",
            json={"asset_id": _FAKE_ASSET_ID, "commit_sha": "a" * 40},
        )
        assert resp.status_code == 403


def test_submit_scan_404_when_asset_not_in_scope():
    """Caller has run_scans but the asset_id isn't in their scope — must 404 without calling submit_scan."""
    other_asset = "ffffffff-1111-2222-3333-444444444444"
    called = {"submit_scan": False}

    async def fake_submit_scan(**kwargs):
        called["submit_scan"] = True
        return None

    with patch("src.authz.enforcement._resolve_effective_permissions", return_value=_WRITER_PERMS), \
         patch("src.scans.manual_router.resolve_asset_ids_from_request", new=AsyncMock(return_value=[other_asset])), \
         patch("src.scans.manual_router.submit_scan", new=fake_submit_scan):
        client = TestClient(_make_app())
        resp = client.post(
            "/api/v1/scans/manual",
            json={"asset_id": _FAKE_ASSET_ID, "commit_sha": "abc1234", "scanner_types": ["dependencies_scanning"]},
        )

    assert resp.status_code == 404
    assert called["submit_scan"] is False


def test_submit_scan_image_asset_returns_501():
    """Image assets reach the dispatcher but raise NotImplementedError → 501."""
    async def raising(**kwargs):
        raise NotImplementedError("per-image scan dispatch not yet wired")

    with patch("src.authz.enforcement._resolve_effective_permissions", return_value=_WRITER_PERMS), \
         patch("src.scans.manual_router.resolve_asset_ids_from_request", new=AsyncMock(return_value=[_FAKE_ASSET_ID])), \
         patch("src.scans.manual_router.submit_scan", new=raising):
        client = TestClient(_make_app())
        resp = client.post(
            "/api/v1/scans/manual",
            json={"asset_id": _FAKE_ASSET_ID, "image_digest": "sha256:abc"},
        )
    assert resp.status_code == 501
    assert "not yet wired" in resp.json()["detail"]


def test_submit_scan_scanner_not_applicable_returns_422():
    """Asking for an unapplicable scanner_type surfaces as 422."""
    from src.scans.service import ScannerNotApplicableError

    async def raising(**kwargs):
        raise ScannerNotApplicableError("scanner_types ['code_scanning'] not applicable to asset_type='image'")

    with patch("src.authz.enforcement._resolve_effective_permissions", return_value=_WRITER_PERMS), \
         patch("src.scans.manual_router.resolve_asset_ids_from_request", new=AsyncMock(return_value=[_FAKE_ASSET_ID])), \
         patch("src.scans.manual_router.submit_scan", new=raising):
        client = TestClient(_make_app())
        resp = client.post(
            "/api/v1/scans/manual",
            json={"asset_id": _FAKE_ASSET_ID, "scanner_types": ["code_scanning"]},
        )
    assert resp.status_code == 422
    assert "not applicable" in resp.json()["detail"]


def test_get_scan_happy_path():
    with patch("src.authz.enforcement._resolve_effective_permissions", return_value=_VIEWER_PERMS), \
         patch("src.scans.router.resolve_asset_ids_from_request", new=AsyncMock(return_value=[_FAKE_ASSET_ID])), \
         patch("src.scans.router.get_scan", new=AsyncMock(return_value=_fake_detail())) as mock_get:
        client = TestClient(_make_app())
        resp = client.get("/api/v1/scans/scan-abc")
        assert resp.status_code == 200
        body = resp.json()
        assert body["scan_id"] == "scan-abc"
        assert body["status"] == "completed"
        assert body["finding_counts"]["high"] == 1
        # Service receives the caller's scoped asset_ids — BOLA contract.
        mock_get.assert_awaited_once_with(scan_id="scan-abc", asset_ids=[_FAKE_ASSET_ID])


def test_get_scan_not_found():
    with patch("src.authz.enforcement._resolve_effective_permissions", return_value=_VIEWER_PERMS), \
         patch("src.scans.router.resolve_asset_ids_from_request", new=AsyncMock(return_value=[_FAKE_ASSET_ID])), \
         patch("src.scans.router.get_scan", new=AsyncMock(return_value=None)):
        client = TestClient(_make_app())
        resp = client.get("/api/v1/scans/scan-missing")
        assert resp.status_code == 404


def test_get_scan_empty_scope_returns_404():
    """Caller has VIEW_FINDINGS but no assets in scope — must 404 fail-closed.

    Replaces the older 'missing org → 400' behaviour: scope is now derived
    from team/grant membership, not a query-param org, so 'no scope' is
    expressed as an empty asset_ids list and surfaces as 404.
    """
    with patch("src.authz.enforcement._resolve_effective_permissions", return_value=_VIEWER_PERMS), \
         patch("src.scans.router.resolve_asset_ids_from_request", new=AsyncMock(return_value=[])), \
         patch("src.scans.router.get_scan", new=AsyncMock(return_value=None)) as mock_get:
        client = TestClient(_make_app())
        resp = client.get("/api/v1/scans/scan-abc")
        assert resp.status_code == 404
        mock_get.assert_awaited_once_with(scan_id="scan-abc", asset_ids=[])


def test_get_scan_out_of_scope_returns_404():
    """BOLA test: scan exists but its asset_id is NOT in the caller's scope.

    The service-layer filter (``WHERE asset_id IN (asset_ids)``) makes
    `get_scan` return None for out-of-scope scans, which surfaces as 404 —
    no existence leak to a probing caller.
    """
    other_asset = "ffffffff-1111-2222-3333-444444444444"
    with patch("src.authz.enforcement._resolve_effective_permissions", return_value=_VIEWER_PERMS), \
         patch("src.scans.router.resolve_asset_ids_from_request", new=AsyncMock(return_value=[other_asset])), \
         patch("src.scans.router.get_scan", new=AsyncMock(return_value=None)) as mock_get:
        client = TestClient(_make_app())
        resp = client.get("/api/v1/scans/scan-abc")
        assert resp.status_code == 404
        mock_get.assert_awaited_once_with(scan_id="scan-abc", asset_ids=[other_asset])


def test_get_scan_surfaces_verification_summary_when_present():
    detail = _fake_detail()
    detail.verification_summary = {
        "confirmed": 2,
        "needs_verify": 1,
        "possible": 0,
        "ruled_out": 3,
        "legacy": 0,
        "tokens_in": 1234,
        "tokens_out": 567,
        "model": "claude-sonnet-4-6",
    }
    with patch("src.authz.enforcement._resolve_effective_permissions", return_value=_VIEWER_PERMS), \
         patch("src.scans.router.resolve_asset_ids_from_request", new=AsyncMock(return_value=[_FAKE_ASSET_ID])), \
         patch("src.scans.router.get_scan", new=AsyncMock(return_value=detail)):
        client = TestClient(_make_app())
        resp = client.get("/api/v1/scans/scan-abc")
        assert resp.status_code == 200
        body = resp.json()
        assert body["verification_summary"]["confirmed"] == 2
        assert body["verification_summary"]["ruled_out"] == 3
        assert body["verification_summary"]["tokens_in"] == 1234
        assert body["verification_summary"]["model"] == "claude-sonnet-4-6"


def test_get_scan_verification_summary_absent_when_legacy():
    with patch("src.authz.enforcement._resolve_effective_permissions", return_value=_VIEWER_PERMS), \
         patch("src.scans.router.resolve_asset_ids_from_request", new=AsyncMock(return_value=[_FAKE_ASSET_ID])), \
         patch("src.scans.router.get_scan", new=AsyncMock(return_value=_fake_detail())):
        client = TestClient(_make_app())
        resp = client.get("/api/v1/scans/scan-abc")
        assert resp.status_code == 200
        body = resp.json()
        assert body["verification_summary"] is None


def test_get_scan_requires_view_findings():
    """Caller without view_findings is rejected before the service is touched."""
    with patch("src.authz.enforcement.dependencies.has_role_permission", return_value=False), \
         patch("src.scans.router.resolve_asset_ids_from_request", new=AsyncMock(return_value=[_FAKE_ASSET_ID])), \
         patch("src.scans.router.get_scan", new=AsyncMock(return_value=_fake_detail())) as mock_get:
        client = TestClient(_make_app(allow_view_findings=False))
        resp = client.get("/api/v1/scans/scan-abc")
        assert resp.status_code == 403
        assert "view_findings" in resp.json()["detail"]
        # Permission check must fire before the service is touched.
        mock_get.assert_not_awaited()


# ─── POST /api/v1/scans/{scan_id}/cancel ──────────────────────────────────────


def _make_cancel_app(*, allow_cancel: bool = True) -> FastAPI:
    """Same shape as _make_app but overrides the CANCEL_SCANS gate."""
    from src.authz.permissions.catalog import CANCEL_SCANS

    app = FastAPI()
    app.include_router(scans_router)

    @app.middleware("http")
    async def inject_user(request: Request, call_next):
        request.state.user_sub = "admin-user"
        request.state.user_role = "admin"
        request.state.user_role_id = None
        return await call_next(request)

    if allow_cancel:
        app.dependency_overrides[Permission(CANCEL_SCANS)] = lambda: None
    return app


def test_cancel_scan_returns_200_with_scan_id_on_active_transition():
    with patch("src.scans.router.resolve_asset_ids_from_request",
               new=AsyncMock(return_value=[_FAKE_ASSET_ID])), \
         patch("src.scans.router.cancel_scan",
               new=AsyncMock(return_value="scan-abc")) as mock_cancel:
        client = TestClient(_make_cancel_app())
        resp = client.post("/api/v1/scans/scan-abc/cancel")
        assert resp.status_code == 200
        body = resp.json()
        assert body["ok"] is True
        assert body["scanId"] == "scan-abc"
        mock_cancel.assert_awaited_once_with(
            scan_id="scan-abc",
            asset_ids=[_FAKE_ASSET_ID],
            actor_user_id="admin-user",
        )


def test_cancel_scan_idempotent_on_already_terminal():
    """Cancel on a completed/failed/cancelled scan returns ok + already_terminal."""
    with patch("src.scans.router.resolve_asset_ids_from_request",
               new=AsyncMock(return_value=[_FAKE_ASSET_ID])), \
         patch("src.scans.router.cancel_scan",
               new=AsyncMock(return_value="already_terminal")):
        client = TestClient(_make_cancel_app())
        resp = client.post("/api/v1/scans/scan-abc/cancel")
        assert resp.status_code == 200
        body = resp.json()
        assert body["ok"] is True
        assert body["already_terminal"] is True
        # No scanId in the terminal-no-op case
        assert "scanId" not in body


def test_cancel_scan_returns_404_when_out_of_scope():
    """Out-of-scope (or non-existent) scan returns 404 to avoid leaking existence."""
    with patch("src.scans.router.resolve_asset_ids_from_request",
               new=AsyncMock(return_value=[_FAKE_ASSET_ID])), \
         patch("src.scans.router.cancel_scan", new=AsyncMock(return_value=None)):
        client = TestClient(_make_cancel_app())
        resp = client.post("/api/v1/scans/scan-abc/cancel")
        assert resp.status_code == 404
        assert resp.json()["detail"] == "Scan not found"


def test_cancel_scan_requires_cancel_scans_permission():
    """Caller without cancel_scans is rejected before the service is touched."""
    with patch("src.authz.enforcement.dependencies.has_role_permission", return_value=False), \
         patch("src.scans.router.resolve_asset_ids_from_request",
               new=AsyncMock(return_value=[_FAKE_ASSET_ID])), \
         patch("src.scans.router.cancel_scan",
               new=AsyncMock(return_value="scan-abc")) as mock_cancel:
        client = TestClient(_make_cancel_app(allow_cancel=False))
        resp = client.post("/api/v1/scans/scan-abc/cancel")
        assert resp.status_code == 403
        assert "cancel_scans" in resp.json()["detail"]
        mock_cancel.assert_not_awaited()


def test_cancel_scan_emits_audit_event_and_sse_on_active_transition():
    """Active cancel must record a scan.cancelled audit event with the actor's
    user_id AND publish a scan.cancelled SSE event so other browser sessions
    refresh in real-time."""
    from src.scans import service as scan_service

    class _FakeRecorder:
        def __init__(self) -> None:
            self.calls: list[dict] = []

        def record(self, *, action: str, resource_type: str, resource_id: str,
                   actor, metadata=None, **_):
            self.calls.append({
                "action": action,
                "resource_type": resource_type,
                "resource_id": resource_id,
                "actor_user_id": getattr(actor, "user_id", None),
                "metadata": metadata or {},
            })

    class _FakeBus:
        def __init__(self) -> None:
            self.events: list = []

        def publish_sync(self, event):
            self.events.append(event)

    class _FakeRow:
        status = "running"
        cancelled_reason = None
        finished_at = None
        error = None
        metadata_json = {
            "scanner_types": ["dependencies_scanning", "secret_scanning"],
            "repo_id": "acme-org/repo-1",
            "org_label": "acme-org",
        }

    class _FakeResult:
        def scalar_one_or_none(self):
            return _FakeRow()

    class _FakeSession:
        async def execute(self, *_a, **_kw):
            return _FakeResult()

        async def commit(self):
            return None

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_a):
            return False

    rec = _FakeRecorder()
    bus = _FakeBus()
    with patch.object(scan_service, "get_session", return_value=_FakeSession()), \
         patch("src.runner.jobs.cancel_jobs_for_scans", return_value=[]), \
         patch("src.audit_log.recorder.get_recorder", return_value=rec), \
         patch("src.shared.event_bus.get_event_bus", return_value=bus):
        import asyncio
        result = asyncio.run(scan_service.cancel_scan(
            scan_id="scan-abc",
            asset_ids=[_FAKE_ASSET_ID],
            actor_user_id="admin-user",
        ))

    assert result == "scan-abc"
    assert len(rec.calls) == 1
    assert rec.calls[0]["action"] == "scan.cancelled"
    assert rec.calls[0]["resource_type"] == "scan_run"
    assert rec.calls[0]["resource_id"] == "scan-abc"
    assert rec.calls[0]["actor_user_id"] == "admin-user"
    assert rec.calls[0]["metadata"]["scanner_types"] == [
        "dependencies_scanning", "secret_scanning",
    ]

    assert len(bus.events) == 1
    assert bus.events[0].event_type == "scan.cancelled"
    assert bus.events[0].data["scanId"] == "scan-abc"
    assert bus.events[0].data["org"] == "acme-org"


# ─── Audit emission on manual scan submission ─────────────────────────────────


class _ManualRecorder:
    def __init__(self) -> None:
        self.calls: list[dict] = []

    def record(self, *, action, resource_type, resource_id=None, actor=None,
               request=None, metadata=None, **_):
        self.calls.append({
            "action": action,
            "resource_type": resource_type,
            "resource_id": resource_id,
            "actor_user_id": getattr(actor, "user_id", None),
            "metadata": metadata or {},
        })


def test_manual_scan_records_scan_triggered_audit_event():
    """User-triggered scans (parallel to the CI-triggered scan.triggered event)
    must leave a compliance trail with the actor's user_id."""
    rec = _ManualRecorder()
    with patch("src.authz.enforcement._resolve_effective_permissions",
               return_value=_WRITER_PERMS), \
         patch("src.scans.manual_router.resolve_asset_ids_from_request",
               new=AsyncMock(return_value=[_FAKE_ASSET_ID])), \
         patch("src.scans.manual_router.submit_scan",
               new=AsyncMock(return_value=_fake_submission())), \
         patch("src.scans.manual_router.get_recorder", return_value=rec):
        client = TestClient(_make_app())
        resp = client.post(
            "/api/v1/scans/manual",
            json={"asset_id": _FAKE_ASSET_ID, "commit_sha": "a" * 40,
                  "scanner_types": ["dependencies_scanning"]},
        )

    assert resp.status_code == 202
    assert len(rec.calls) == 1
    assert rec.calls[0]["action"] == "scan.triggered"
    assert rec.calls[0]["resource_type"] == "scan_run"
    assert rec.calls[0]["resource_id"] == "scan-abc"
    assert rec.calls[0]["actor_user_id"] == "admin-user"
    assert rec.calls[0]["metadata"]["triggered_by"] == "user"
    assert rec.calls[0]["metadata"]["asset_id"] == _FAKE_ASSET_ID


def test_manual_scan_audit_failure_does_not_break_submission():
    """A misbehaving recorder must not turn a successful scan submission into
    a 5xx — the scan_id is already committed, swallow the audit error."""
    class _ExplodingRecorder:
        def record(self, **_):
            raise RuntimeError("audit backend down")

    with patch("src.authz.enforcement._resolve_effective_permissions",
               return_value=_WRITER_PERMS), \
         patch("src.scans.manual_router.resolve_asset_ids_from_request",
               new=AsyncMock(return_value=[_FAKE_ASSET_ID])), \
         patch("src.scans.manual_router.submit_scan",
               new=AsyncMock(return_value=_fake_submission())), \
         patch("src.scans.manual_router.get_recorder",
               return_value=_ExplodingRecorder()):
        client = TestClient(_make_app())
        resp = client.post(
            "/api/v1/scans/manual",
            json={"asset_id": _FAKE_ASSET_ID, "commit_sha": "a" * 40,
                  "scanner_types": ["dependencies_scanning"]},
        )

    assert resp.status_code == 202
    assert resp.json()["scan_id"] == "scan-abc"
