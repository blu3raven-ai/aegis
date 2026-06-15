"""Smoke tests for the findings REST router — auth + asset-scope enforcement.

Mocks the DB session, lifecycle helpers, and service layer so we can verify the
router resolves viewer asset_ids and rejects out-of-scope finding ids before
mutating state.
"""
from __future__ import annotations

import os
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost:5432/test")
os.environ.setdefault("RUNNER_ENCRYPTION_KEY", "0" * 64)

from src.findings.router import router as findings_router  # noqa: E402

_FAKE_ASSET_ID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
_OTHER_ASSET_ID = "bbbbbbbb-cccc-dddd-eeee-ffffffffffff"
_VALID_REASON = "Risk is tolerable"


def _make_app() -> FastAPI:
    app = FastAPI()
    app.include_router(findings_router)

    @app.middleware("http")
    async def inject_user(request: Request, call_next):
        request.state.user_sub = "viewer-1"
        request.state.user_role = "viewer"
        request.state.user_role_id = None
        return await call_next(request)

    return app


class _Session:
    """Minimal async context manager standing in for get_session()."""

    def __init__(self, findings):
        self._findings = findings

    async def __aenter__(self):
        scalars = MagicMock()
        scalars.first.return_value = self._findings[0] if self._findings else None
        scalars.all.return_value = self._findings
        result = MagicMock()
        result.scalars.return_value = scalars
        session = MagicMock()
        session.execute = AsyncMock(return_value=result)
        return session

    async def __aexit__(self, *args):
        return None


def _finding(*, id: int, asset_id: str | None, tool: str = "dependencies", key: str = "k") -> SimpleNamespace:
    return SimpleNamespace(id=id, asset_id=asset_id, tool=tool, identity_key=key, org="acme")


# ─── POST /findings/{id}/dismiss ────────────────────────────────────────────


def test_dismiss_calls_lifecycle_when_asset_in_scope():
    finding = _finding(id=42, asset_id=_FAKE_ASSET_ID)
    dismissed = {}

    def fake_dismiss(tool, key, reason, user_id, comment, *, asset_id=None, org=None):
        dismissed["asset_id"] = asset_id

    with patch("src.findings.router.require_permission"), \
         patch("src.findings.router.resolve_asset_ids_from_request",
               new=AsyncMock(return_value=[_FAKE_ASSET_ID])), \
         patch("src.findings.router.get_session", return_value=_Session([finding])), \
         patch("src.findings.router.dismiss_finding", side_effect=fake_dismiss):
        client = TestClient(_make_app())
        resp = client.post("/api/v1/findings/42/dismiss", json={"reason": _VALID_REASON})

    assert resp.status_code == 200
    assert dismissed["asset_id"] == _FAKE_ASSET_ID


def test_dismiss_returns_404_when_asset_out_of_scope():
    finding = _finding(id=42, asset_id=_OTHER_ASSET_ID)
    called = {"dismiss": False}

    def fake_dismiss(*args, **kwargs):
        called["dismiss"] = True

    with patch("src.findings.router.require_permission"), \
         patch("src.findings.router.resolve_asset_ids_from_request",
               new=AsyncMock(return_value=[_FAKE_ASSET_ID])), \
         patch("src.findings.router.get_session", return_value=_Session([finding])), \
         patch("src.findings.router.dismiss_finding", side_effect=fake_dismiss):
        client = TestClient(_make_app())
        resp = client.post("/api/v1/findings/42/dismiss", json={"reason": _VALID_REASON})

    assert resp.status_code == 404
    assert called["dismiss"] is False


def test_dismiss_returns_404_for_secrets_finding_with_null_asset_id():
    finding = _finding(id=42, asset_id=None, tool="secrets")
    called = {"dismiss": False}

    def fake_dismiss(*args, **kwargs):
        called["dismiss"] = True

    with patch("src.findings.router.require_permission"), \
         patch("src.findings.router.resolve_asset_ids_from_request",
               new=AsyncMock(return_value=[_FAKE_ASSET_ID])), \
         patch("src.findings.router.get_session", return_value=_Session([finding])), \
         patch("src.findings.router.dismiss_finding", side_effect=fake_dismiss):
        client = TestClient(_make_app())
        resp = client.post("/api/v1/findings/42/dismiss", json={"reason": _VALID_REASON})

    assert resp.status_code == 404
    assert called["dismiss"] is False


def test_dismiss_returns_404_when_finding_missing():
    with patch("src.findings.router.require_permission"), \
         patch("src.findings.router.resolve_asset_ids_from_request",
               new=AsyncMock(return_value=[_FAKE_ASSET_ID])), \
         patch("src.findings.router.get_session", return_value=_Session([])):
        client = TestClient(_make_app())
        resp = client.post("/api/v1/findings/999/dismiss", json={"reason": _VALID_REASON})
    assert resp.status_code == 404


# ─── POST /findings/bulk_dismiss ────────────────────────────────────────────


def test_bulk_dismiss_only_processes_in_scope_findings():
    in_scope = _finding(id=1, asset_id=_FAKE_ASSET_ID, key="key-1")
    out_of_scope = _finding(id=2, asset_id=_OTHER_ASSET_ID, key="key-2")
    captured_calls: list[dict] = []

    def fake_bulk(tool, keys, reason, user_id, comment, *, asset_ids=None, secrets=False):
        captured_calls.append({"tool": tool, "keys": list(keys), "asset_ids": asset_ids, "secrets": secrets})
        return len(keys)

    with patch("src.findings.router.require_permission"), \
         patch("src.findings.router.resolve_asset_ids_from_request",
               new=AsyncMock(return_value=[_FAKE_ASSET_ID])), \
         patch("src.findings.router.get_session", return_value=_Session([in_scope, out_of_scope])), \
         patch("src.findings.router.bulk_dismiss", side_effect=fake_bulk):
        client = TestClient(_make_app())
        resp = client.post(
            "/api/v1/findings/bulk_dismiss",
            json={"ids": [1, 2], "reason": _VALID_REASON},
        )

    assert resp.status_code == 200
    assert resp.json() == {"ok": True, "updated": 1}
    assert len(captured_calls) == 1
    assert captured_calls[0]["keys"] == ["key-1"]
    assert captured_calls[0]["asset_ids"] == [_FAKE_ASSET_ID]


def test_bulk_dismiss_drops_secrets_findings_with_null_asset_id():
    secrets_row = _finding(id=3, asset_id=None, tool="secrets", key="leaked")
    called = {"bulk": 0}

    def fake_bulk(*args, **kwargs):
        called["bulk"] += 1
        return 0

    with patch("src.findings.router.require_permission"), \
         patch("src.findings.router.resolve_asset_ids_from_request",
               new=AsyncMock(return_value=[_FAKE_ASSET_ID])), \
         patch("src.findings.router.get_session", return_value=_Session([secrets_row])), \
         patch("src.findings.router.bulk_dismiss", side_effect=fake_bulk):
        client = TestClient(_make_app())
        resp = client.post(
            "/api/v1/findings/bulk_dismiss",
            json={"ids": [3], "reason": _VALID_REASON},
        )

    assert resp.status_code == 200
    assert resp.json() == {"ok": True, "updated": 0}
    assert called["bulk"] == 0


def test_bulk_dismiss_with_empty_scope_dismisses_nothing():
    in_scope = _finding(id=1, asset_id=_FAKE_ASSET_ID)
    called = {"bulk": 0}

    def fake_bulk(*args, **kwargs):
        called["bulk"] += 1
        return 1

    with patch("src.findings.router.require_permission"), \
         patch("src.findings.router.resolve_asset_ids_from_request",
               new=AsyncMock(return_value=[])), \
         patch("src.findings.router.get_session", return_value=_Session([in_scope])), \
         patch("src.findings.router.bulk_dismiss", side_effect=fake_bulk):
        client = TestClient(_make_app())
        resp = client.post(
            "/api/v1/findings/bulk_dismiss",
            json={"ids": [1], "reason": _VALID_REASON},
        )

    assert resp.status_code == 200
    assert resp.json() == {"ok": True, "updated": 0}
    assert called["bulk"] == 0


# ─── PATCH /findings/{id}/assignee ──────────────────────────────────────────


def test_assignee_threads_asset_ids_into_service():
    captured: dict = {}

    async def fake_assign(finding_id, assignee, session, asset_ids):
        captured["finding_id"] = finding_id
        captured["asset_ids"] = asset_ids
        finding = SimpleNamespace(id=finding_id, assignee_user_id=assignee)
        return finding, None

    with patch("src.findings.router.require_permission"), \
         patch("src.findings.router.resolve_asset_ids_from_request",
               new=AsyncMock(return_value=[_FAKE_ASSET_ID])), \
         patch("src.findings.router.get_session", return_value=_Session([])), \
         patch("src.findings.router.assign_finding", new=fake_assign), \
         patch("src.findings.router._finding_to_dict",
               return_value={"id": 42, "assignee_user_id": "alice"}), \
         patch("src.findings.router.record_event"):
        client = TestClient(_make_app())
        resp = client.patch(
            "/api/v1/findings/42/assignee",
            json={"assignee_user_id": "alice"},
        )

    assert resp.status_code == 200
    assert captured["asset_ids"] == [_FAKE_ASSET_ID]


def test_assignee_returns_404_when_service_raises_lookup_error():
    async def fake_assign(*args, **kwargs):
        raise LookupError("finding 42 not found")

    with patch("src.findings.router.require_permission"), \
         patch("src.findings.router.resolve_asset_ids_from_request",
               new=AsyncMock(return_value=[_OTHER_ASSET_ID])), \
         patch("src.findings.router.get_session", return_value=_Session([])), \
         patch("src.findings.router.assign_finding", new=fake_assign):
        client = TestClient(_make_app())
        resp = client.patch(
            "/api/v1/findings/42/assignee",
            json={"assignee_user_id": "alice"},
        )

    assert resp.status_code == 404
