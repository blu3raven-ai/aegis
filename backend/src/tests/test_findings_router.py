"""Smoke tests for the findings REST router — auth + asset-scope enforcement.

Mocks the DB session, lifecycle helpers, and service layer so we can verify the
unified PATCH /findings/{id} and PATCH /findings endpoints resolve viewer
asset_ids and reject out-of-scope finding ids before mutating state.
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


def _finding(*, id: int, asset_id: str | None, tool: str = "dependencies_scanning", key: str = "k") -> SimpleNamespace:
    return SimpleNamespace(id=id, asset_id=asset_id, tool=tool, identity_key=key, org="acme")


# ---------------------------------------------------------------------------
# PATCH /findings/{id} — single mutation
# ---------------------------------------------------------------------------


def test_patch_finding_dismiss_calls_lifecycle_when_asset_in_scope():
    finding = _finding(id=42, asset_id=_FAKE_ASSET_ID)
    dismissed = {}

    def fake_dismiss(tool, key, reason, user_id, comment, *, asset_id=None, org=None):
        dismissed["asset_id"] = asset_id
        dismissed["reason"] = reason

    with patch("src.findings.router.require_permission"), \
         patch("src.findings.router.resolve_asset_ids_from_request",
               new=AsyncMock(return_value=[_FAKE_ASSET_ID])), \
         patch("src.findings.router.get_session", return_value=_Session([finding])), \
         patch("src.findings.router.dismiss_finding", side_effect=fake_dismiss):
        client = TestClient(_make_app())
        resp = client.patch(
            "/api/v1/findings/42",
            json={"state": "dismissed", "dismiss_reason": _VALID_REASON},
        )

    assert resp.status_code == 200
    assert dismissed["asset_id"] == _FAKE_ASSET_ID
    assert dismissed["reason"] == _VALID_REASON


def test_patch_finding_dismiss_returns_404_when_asset_out_of_scope():
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
        resp = client.patch(
            "/api/v1/findings/42",
            json={"state": "dismissed", "dismiss_reason": _VALID_REASON},
        )

    assert resp.status_code == 404
    assert called["dismiss"] is False


def test_patch_finding_returns_404_for_secrets_finding_with_null_asset_id():
    finding = _finding(id=42, asset_id=None, tool="secret_scanning")

    with patch("src.findings.router.require_permission"), \
         patch("src.findings.router.resolve_asset_ids_from_request",
               new=AsyncMock(return_value=[_FAKE_ASSET_ID])), \
         patch("src.findings.router.get_session", return_value=_Session([finding])), \
         patch("src.findings.router.dismiss_finding"):
        client = TestClient(_make_app())
        resp = client.patch(
            "/api/v1/findings/42",
            json={"state": "dismissed", "dismiss_reason": _VALID_REASON},
        )

    assert resp.status_code == 404


def test_patch_finding_returns_404_when_finding_missing():
    with patch("src.findings.router.require_permission"), \
         patch("src.findings.router.resolve_asset_ids_from_request",
               new=AsyncMock(return_value=[_FAKE_ASSET_ID])), \
         patch("src.findings.router.get_session", return_value=_Session([])):
        client = TestClient(_make_app())
        resp = client.patch(
            "/api/v1/findings/999",
            json={"state": "dismissed", "dismiss_reason": _VALID_REASON},
        )
    assert resp.status_code == 404


def test_patch_finding_rejects_invalid_dismiss_reason():
    with patch("src.findings.router.require_permission"):
        client = TestClient(_make_app())
        resp = client.patch(
            "/api/v1/findings/42",
            json={"state": "dismissed", "dismiss_reason": "bogus"},
        )
    assert resp.status_code == 400


def test_patch_finding_requires_reason_when_state_is_dismissed():
    with patch("src.findings.router.require_permission"):
        client = TestClient(_make_app())
        resp = client.patch("/api/v1/findings/42", json={"state": "dismissed"})
    assert resp.status_code == 400


def test_patch_finding_rejects_empty_body():
    with patch("src.findings.router.require_permission"):
        client = TestClient(_make_app())
        resp = client.patch("/api/v1/findings/42", json={})
    assert resp.status_code == 400


def test_patch_finding_assigns_when_in_scope():
    finding = _finding(id=42, asset_id=_FAKE_ASSET_ID)
    captured: dict = {}

    async def fake_assign(finding_id, assignee, session, asset_ids):
        captured["finding_id"] = finding_id
        captured["asset_ids"] = asset_ids
        return SimpleNamespace(id=finding_id, assignee_user_id=assignee), None

    with patch("src.findings.router.require_permission"), \
         patch("src.findings.router.resolve_asset_ids_from_request",
               new=AsyncMock(return_value=[_FAKE_ASSET_ID])), \
         patch("src.findings.router.get_session", return_value=_Session([finding])), \
         patch("src.findings.router.assign_finding", new=fake_assign), \
         patch("src.findings.router._finding_to_dict",
               return_value={"id": 42, "assignee_user_id": "alice"}), \
         patch("src.findings.router.record_event"):
        client = TestClient(_make_app())
        resp = client.patch(
            "/api/v1/findings/42",
            json={"assignee_user_id": "alice"},
        )

    assert resp.status_code == 200
    assert captured["asset_ids"] == [_FAKE_ASSET_ID]


def test_patch_finding_assignee_returns_404_when_service_raises_lookup_error():
    async def fake_assign(*args, **kwargs):
        raise LookupError("finding 42 not found")

    with patch("src.findings.router.require_permission"), \
         patch("src.findings.router.resolve_asset_ids_from_request",
               new=AsyncMock(return_value=[_OTHER_ASSET_ID])), \
         patch("src.findings.router.get_session", return_value=_Session([])), \
         patch("src.findings.router.assign_finding", new=fake_assign):
        client = TestClient(_make_app())
        resp = client.patch(
            "/api/v1/findings/42",
            json={"assignee_user_id": "alice"},
        )

    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# PATCH /findings — bulk mutation
# ---------------------------------------------------------------------------


def test_bulk_patch_dismiss_only_processes_in_scope_findings():
    in_scope = _finding(id=1, asset_id=_FAKE_ASSET_ID, key="key-1")
    out_of_scope = _finding(id=2, asset_id=_OTHER_ASSET_ID, key="key-2")
    captured_calls: list[dict] = []

    async def fake_bulk(session, tool, keys, reason, user_id, comment, *, asset_ids=None, org=None, secrets=False):
        captured_calls.append({"tool": tool, "keys": list(keys), "asset_ids": asset_ids})
        return len(keys)

    with patch("src.findings.router.require_permission"), \
         patch("src.findings.router.resolve_asset_ids_from_request",
               new=AsyncMock(return_value=[_FAKE_ASSET_ID])), \
         patch("src.findings.router.get_session", return_value=_Session([in_scope, out_of_scope])), \
         patch("src.findings.router.bulk_dismiss_in_session", side_effect=fake_bulk):
        client = TestClient(_make_app())
        resp = client.patch(
            "/api/v1/findings",
            json={"ids": [1, 2], "state": "dismissed", "dismiss_reason": _VALID_REASON},
        )

    assert resp.status_code == 200
    assert resp.json() == {"ok": True, "updated": 1}
    assert len(captured_calls) == 1
    assert captured_calls[0]["keys"] == ["key-1"]
    assert captured_calls[0]["asset_ids"] == [_FAKE_ASSET_ID]


def test_bulk_patch_dismiss_drops_secrets_findings_with_null_asset_id():
    secrets_row = _finding(id=3, asset_id=None, tool="secret_scanning", key="leaked")
    called = {"bulk": 0}

    async def fake_bulk(*args, **kwargs):
        called["bulk"] += 1
        return 0

    with patch("src.findings.router.require_permission"), \
         patch("src.findings.router.resolve_asset_ids_from_request",
               new=AsyncMock(return_value=[_FAKE_ASSET_ID])), \
         patch("src.findings.router.get_session", return_value=_Session([secrets_row])), \
         patch("src.findings.router.bulk_dismiss_in_session", side_effect=fake_bulk):
        client = TestClient(_make_app())
        resp = client.patch(
            "/api/v1/findings",
            json={"ids": [3], "state": "dismissed", "dismiss_reason": _VALID_REASON},
        )

    assert resp.status_code == 200
    assert resp.json() == {"ok": True, "updated": 0}
    assert called["bulk"] == 0


def test_bulk_patch_with_empty_scope_dismisses_nothing():
    in_scope = _finding(id=1, asset_id=_FAKE_ASSET_ID)
    called = {"bulk": 0}

    async def fake_bulk(*args, **kwargs):
        called["bulk"] += 1
        return 1

    with patch("src.findings.router.require_permission"), \
         patch("src.findings.router.resolve_asset_ids_from_request",
               new=AsyncMock(return_value=[])), \
         patch("src.findings.router.get_session", return_value=_Session([in_scope])), \
         patch("src.findings.router.bulk_dismiss_in_session", side_effect=fake_bulk):
        client = TestClient(_make_app())
        resp = client.patch(
            "/api/v1/findings",
            json={"ids": [1], "state": "dismissed", "dismiss_reason": _VALID_REASON},
        )

    assert resp.status_code == 200
    assert resp.json() == {"ok": True, "updated": 0}
    assert called["bulk"] == 0


def test_bulk_patch_processes_all_groups_in_single_session():
    """All (tool, asset_id) groups share one AsyncSession — atomic transaction."""
    findings = [
        _finding(id=1, asset_id=_FAKE_ASSET_ID, tool="dependencies_scanning", key="dep-1"),
        _finding(id=2, asset_id=_FAKE_ASSET_ID, tool="code_scanning", key="cs-1"),
        _finding(id=3, asset_id=_OTHER_ASSET_ID, tool="dependencies_scanning", key="dep-2"),
    ]
    captured_sessions: list = []

    async def fake_bulk(session, tool, keys, reason, user_id, comment, *,
                       asset_ids=None, org=None, secrets=False):
        captured_sessions.append(id(session))
        return len(keys)

    with patch("src.findings.router.require_permission"), \
         patch("src.findings.router.resolve_asset_ids_from_request",
               new=AsyncMock(return_value=[_FAKE_ASSET_ID, _OTHER_ASSET_ID])), \
         patch("src.findings.router.get_session", return_value=_Session(findings)), \
         patch("src.findings.router.bulk_dismiss_in_session", side_effect=fake_bulk):
        client = TestClient(_make_app())
        resp = client.patch(
            "/api/v1/findings",
            json={"ids": [1, 2, 3], "state": "dismissed", "dismiss_reason": _VALID_REASON},
        )

    assert resp.status_code == 200
    # Multiple groups, all running on the same session id.
    assert len(captured_sessions) >= 1
    assert len(set(captured_sessions)) == 1, (
        "expected a single shared session across groups, got: "
        f"{captured_sessions}"
    )


def test_bulk_patch_rejects_empty_ids():
    with patch("src.findings.router.require_permission"):
        client = TestClient(_make_app())
        resp = client.patch(
            "/api/v1/findings",
            json={"ids": [], "state": "dismissed", "dismiss_reason": _VALID_REASON},
        )
    assert resp.status_code == 400


def test_bulk_patch_caps_ids_count():
    with patch("src.findings.router.require_permission"):
        client = TestClient(_make_app())
        resp = client.patch(
            "/api/v1/findings",
            json={
                "ids": list(range(1001)),
                "state": "dismissed",
                "dismiss_reason": _VALID_REASON,
            },
        )
    assert resp.status_code == 400


def test_bulk_patch_rejects_invalid_dismiss_reason():
    with patch("src.findings.router.require_permission"):
        client = TestClient(_make_app())
        resp = client.patch(
            "/api/v1/findings",
            json={"ids": [1], "state": "dismissed", "dismiss_reason": "bogus"},
        )
    assert resp.status_code == 400


# ---------------------------------------------------------------------------
# Audit emission — dismiss + reopen state transitions
# ---------------------------------------------------------------------------


def test_dismiss_finding_records_finding_dismissed_audit_event():
    """Dismissing a finding accepts risk on behalf of the org — must leave a
    trail with reason and identifying metadata."""
    finding = _finding(id=42, asset_id=_FAKE_ASSET_ID)
    records: list[dict] = []

    def fake_record(*, action, actor_user_id=None, target=None, metadata=None, **_):
        records.append({"action": action, "actor_user_id": actor_user_id,
                        "target": target, "metadata": metadata or {}})

    with patch("src.findings.router.require_permission"), \
         patch("src.findings.router.resolve_asset_ids_from_request",
               new=AsyncMock(return_value=[_FAKE_ASSET_ID])), \
         patch("src.findings.router.get_session", return_value=_Session([finding])), \
         patch("src.findings.router.dismiss_finding"), \
         patch("src.findings.router.record_event", side_effect=fake_record):
        client = TestClient(_make_app())
        resp = client.patch(
            "/api/v1/findings/42",
            json={"state": "dismissed", "dismiss_reason": _VALID_REASON,
                  "comment": "false positive"},
        )

    assert resp.status_code == 200
    assert len(records) == 1
    assert records[0]["action"] == "finding.dismissed"
    assert records[0]["target"] == "42"
    assert records[0]["actor_user_id"] == "viewer-1"
    assert records[0]["metadata"]["dismiss_reason"] == _VALID_REASON
    assert records[0]["metadata"]["comment"] == "false positive"
    assert records[0]["metadata"]["tool"] == "dependencies_scanning"


def test_reopen_finding_records_finding_reopened_audit_event():
    finding = _finding(id=42, asset_id=_FAKE_ASSET_ID)
    records: list[dict] = []

    def fake_record(*, action, actor_user_id=None, target=None, metadata=None, **_):
        records.append({"action": action, "target": target,
                        "actor_user_id": actor_user_id,
                        "metadata": metadata or {}})

    with patch("src.findings.router.require_permission"), \
         patch("src.findings.router.resolve_asset_ids_from_request",
               new=AsyncMock(return_value=[_FAKE_ASSET_ID])), \
         patch("src.findings.router.get_session", return_value=_Session([finding])), \
         patch("src.findings.router.reopen_finding"), \
         patch("src.findings.router.record_event", side_effect=fake_record):
        client = TestClient(_make_app())
        resp = client.patch("/api/v1/findings/42", json={"state": "open"})

    assert resp.status_code == 200
    assert len(records) == 1
    assert records[0]["action"] == "finding.reopened"
    assert records[0]["target"] == "42"
    assert records[0]["metadata"]["tool"] == "dependencies_scanning"


def test_bulk_dismiss_records_one_audit_event_per_finding_with_bulk_flag():
    findings = [
        _finding(id=1, asset_id=_FAKE_ASSET_ID, key="k1"),
        _finding(id=2, asset_id=_FAKE_ASSET_ID, key="k2"),
    ]
    records: list[dict] = []

    def fake_record(*, action, actor_user_id=None, target=None, metadata=None, **_):
        records.append({"action": action, "target": target,
                        "metadata": metadata or {}})

    async def fake_bulk_dismiss(*args, **kwargs):
        return 2

    with patch("src.findings.router.require_permission"), \
         patch("src.findings.router.resolve_asset_ids_from_request",
               new=AsyncMock(return_value=[_FAKE_ASSET_ID])), \
         patch("src.findings.router.get_session", return_value=_Session(findings)), \
         patch("src.findings.router.bulk_dismiss_in_session",
               new=AsyncMock(side_effect=fake_bulk_dismiss)), \
         patch("src.findings.router.request_home_views_refresh"), \
         patch("src.findings.router.record_event", side_effect=fake_record):
        client = TestClient(_make_app())
        resp = client.patch(
            "/api/v1/findings",
            json={"ids": [1, 2], "state": "dismissed",
                  "dismiss_reason": _VALID_REASON},
        )

    assert resp.status_code == 200
    actions = [r["action"] for r in records]
    assert actions == ["finding.dismissed", "finding.dismissed"]
    targets = sorted(r["target"] for r in records)
    assert targets == ["1", "2"]
    assert all(r["metadata"].get("bulk") is True for r in records)
