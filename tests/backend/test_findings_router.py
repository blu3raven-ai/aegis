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
os.environ.setdefault("APP_SECRET", "0" * 64)

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

    def __init__(self, findings, user_rows=None):
        self._findings = findings
        self._user_rows = user_rows or []
        self.statements = []  # SQL statements passed to execute(), for scope assertions

    async def __aenter__(self):
        scalars = MagicMock()
        scalars.first.return_value = self._findings[0] if self._findings else None
        scalars.all.return_value = self._findings
        result = MagicMock()
        result.scalars.return_value = scalars
        result.all.return_value = self._user_rows  # (id, username) rows for resolution
        session = MagicMock()

        async def _execute(stmt, *args, **kwargs):
            self.statements.append(stmt)
            return result

        session.execute = AsyncMock(side_effect=_execute)
        # Detail path resolves Asset.display_name via scalar() for the repo ref.
        session.scalar = AsyncMock(return_value="github:acme/api")
        session.add = MagicMock()
        session.commit = AsyncMock()
        session.refresh = AsyncMock()
        return session

    async def __aexit__(self, *args):
        return None


def _finding(*, id: int, asset_id: str | None, tool: str = "dependencies_scanning", key: str = "k", detail: dict | None = None) -> SimpleNamespace:
    return SimpleNamespace(id=id, asset_id=asset_id, tool=tool, identity_key=key, org="acme", severity="high", detail=detail or {})


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
         patch("src.findings.router.notify_finding_assigned", new=AsyncMock()), \
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
# POST/GET /findings/{id}/comments
# ---------------------------------------------------------------------------


def test_add_comment_stores_and_returns_it_when_in_scope():
    finding = _finding(id=42, asset_id=_FAKE_ASSET_ID)
    with patch("src.findings.router.require_permission"), \
         patch("src.findings.router.resolve_asset_ids_from_request",
               new=AsyncMock(return_value=[_FAKE_ASSET_ID])), \
         patch("src.findings.router.get_session", return_value=_Session([finding])), \
         patch("src.findings.router.record_event") as rec:
        client = TestClient(_make_app())
        resp = client.post("/api/v1/findings/42/comments", json={"comment": "looks exploitable"})
    assert resp.status_code == 200
    assert resp.json()["comment"]["body"] == "looks exploitable"
    rec.assert_called_once()


def test_add_comment_resolves_actor_to_username():
    finding = _finding(id=42, asset_id=_FAKE_ASSET_ID)
    with patch("src.findings.router.require_permission"), \
         patch("src.findings.router.resolve_asset_ids_from_request",
               new=AsyncMock(return_value=[_FAKE_ASSET_ID])), \
         patch("src.findings.router.get_session",
               return_value=_Session([finding], user_rows=[("viewer-1", "alice")])), \
         patch("src.findings.router.record_event"):
        client = TestClient(_make_app())
        resp = client.post("/api/v1/findings/42/comments", json={"comment": "looks real"})
    assert resp.status_code == 200
    assert resp.json()["comment"]["actor"] == "alice"


def test_add_comment_rejects_empty():
    with patch("src.findings.router.require_permission"):
        client = TestClient(_make_app())
        resp = client.post("/api/v1/findings/42/comments", json={"comment": "   "})
    assert resp.status_code == 400


def test_add_comment_404_when_out_of_scope():
    finding = _finding(id=42, asset_id=_OTHER_ASSET_ID)
    with patch("src.findings.router.require_permission"), \
         patch("src.findings.router.resolve_asset_ids_from_request",
               new=AsyncMock(return_value=[_FAKE_ASSET_ID])), \
         patch("src.findings.router.get_session", return_value=_Session([finding])), \
         patch("src.findings.router.record_event") as rec:
        client = TestClient(_make_app())
        resp = client.post("/api/v1/findings/42/comments", json={"comment": "hi"})
    assert resp.status_code == 404
    rec.assert_not_called()


def test_get_finding_detail_returns_dict_when_in_scope():
    finding = _finding(id=42, asset_id=_FAKE_ASSET_ID)
    with patch("src.findings.router.require_permission"), \
         patch("src.findings.router.resolve_asset_ids_from_request",
               new=AsyncMock(return_value=[_FAKE_ASSET_ID])), \
         patch("src.findings.router.get_session", return_value=_Session([finding])), \
         patch("src.findings.router.count_related_repos", new=AsyncMock(return_value=3)), \
         patch("src.findings.router._finding_to_dict",
               return_value={"id": "42", "description": "boom", "rule": "r"}):
        client = TestClient(_make_app())
        resp = client.get("/api/v1/findings/42")
    assert resp.status_code == 200
    assert resp.json() == {
        "finding": {"id": "42", "description": "boom", "rule": "r", "also_affects_repos": 3}
    }


def test_get_finding_detail_404_when_out_of_scope():
    finding = _finding(id=42, asset_id=_OTHER_ASSET_ID)
    with patch("src.findings.router.require_permission"), \
         patch("src.findings.router.resolve_asset_ids_from_request",
               new=AsyncMock(return_value=[_FAKE_ASSET_ID])), \
         patch("src.findings.router.get_session", return_value=_Session([finding])):
        client = TestClient(_make_app())
        resp = client.get("/api/v1/findings/42")
    assert resp.status_code == 404


def test_list_comments_404_when_out_of_scope():
    finding = _finding(id=42, asset_id=_OTHER_ASSET_ID)
    with patch("src.findings.router.require_permission"), \
         patch("src.findings.router.resolve_asset_ids_from_request",
               new=AsyncMock(return_value=[_FAKE_ASSET_ID])), \
         patch("src.findings.router.get_session", return_value=_Session([finding])):
        client = TestClient(_make_app())
        resp = client.get("/api/v1/findings/42/comments")
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


def test_defer_finding_calls_lifecycle_and_records_audit():
    finding = _finding(id=42, asset_id=_FAKE_ASSET_ID)
    deferred = {"called": False}
    records: list[dict] = []

    def fake_defer(tool, key, user_id, *, asset_id=None, org=None):
        deferred["called"] = True
        deferred["asset_id"] = asset_id

    def fake_record(*, action, actor_user_id=None, target=None, metadata=None, **_):
        records.append({"action": action, "target": target})

    with patch("src.findings.router.require_permission"), \
         patch("src.findings.router.resolve_asset_ids_from_request",
               new=AsyncMock(return_value=[_FAKE_ASSET_ID])), \
         patch("src.findings.router.get_session", return_value=_Session([finding])), \
         patch("src.findings.router.defer_finding", side_effect=fake_defer), \
         patch("src.findings.router.record_event", side_effect=fake_record):
        client = TestClient(_make_app())
        resp = client.patch("/api/v1/findings/42", json={"state": "deferred"})

    assert resp.status_code == 200
    assert deferred == {"called": True, "asset_id": _FAKE_ASSET_ID}
    assert records == [{"action": "finding.deferred", "target": "42"}]


def test_defer_finding_returns_404_when_out_of_scope():
    finding = _finding(id=42, asset_id=_OTHER_ASSET_ID)
    with patch("src.findings.router.require_permission"), \
         patch("src.findings.router.resolve_asset_ids_from_request",
               new=AsyncMock(return_value=[_FAKE_ASSET_ID])), \
         patch("src.findings.router.get_session", return_value=_Session([finding])), \
         patch("src.findings.router.defer_finding") as deferred:
        client = TestClient(_make_app())
        resp = client.patch("/api/v1/findings/42", json={"state": "deferred"})
    assert resp.status_code == 404
    deferred.assert_not_called()


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


# ---------------------------------------------------------------------------
# GET /findings/{id}/advisory — Security Brief enrichment
# ---------------------------------------------------------------------------

_ADVISORY_DETAIL = {
    "advisoryId": "GHSA-wr9h-g72x-mwhm",
    "cveId": "CVE-2025-59425",
    "cvssVector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "summary": "vLLM denial of service",
    "vulnerableVersionRange": ">= 0, < 0.11.0",
    "patchedVersion": "0.11.0",
    "references": [{"url": "https://github.com/advisories/GHSA-wr9h-g72x-mwhm"}],
}


def test_get_advisory_returns_404_when_asset_out_of_scope():
    finding = _finding(id=42, asset_id=_OTHER_ASSET_ID, detail=_ADVISORY_DETAIL)
    with patch("src.findings.router.require_permission"), \
         patch("src.findings.router.resolve_asset_ids_from_request",
               new=AsyncMock(return_value=[_FAKE_ASSET_ID])), \
         patch("src.findings.router.get_session", return_value=_Session([finding])):
        client = TestClient(_make_app())
        resp = client.get("/api/v1/findings/42/advisory")
    assert resp.status_code == 404


def test_get_related_returns_404_when_asset_out_of_scope():
    finding = _finding(id=42, asset_id=_OTHER_ASSET_ID)
    with patch("src.findings.router.require_permission"), \
         patch("src.findings.router.resolve_asset_ids_from_request",
               new=AsyncMock(return_value=[_FAKE_ASSET_ID])), \
         patch("src.findings.router.get_session", return_value=_Session([finding])), \
         patch("src.findings.router.list_related_findings", new=AsyncMock(return_value=[])):
        client = TestClient(_make_app())
        resp = client.get("/api/v1/findings/42/related")
    assert resp.status_code == 404


def test_get_related_returns_list_for_scoped_finding():
    finding = _finding(id=42, asset_id=_FAKE_ASSET_ID)
    related = [{"finding_id": "7", "repo": "acme/api", "severity": "high", "state": "open"}]
    with patch("src.findings.router.require_permission"), \
         patch("src.findings.router.resolve_asset_ids_from_request",
               new=AsyncMock(return_value=[_FAKE_ASSET_ID])), \
         patch("src.findings.router.get_session", return_value=_Session([finding])), \
         patch("src.findings.router.list_related_findings", new=AsyncMock(return_value=related)):
        client = TestClient(_make_app())
        resp = client.get("/api/v1/findings/42/related")
    assert resp.status_code == 200
    assert resp.json() == {"related": related}


def test_get_advisory_returns_null_for_finding_without_advisory():
    finding = _finding(id=42, asset_id=_FAKE_ASSET_ID, tool="code_scanning", detail={})
    with patch("src.findings.router.require_permission"), \
         patch("src.findings.router.resolve_asset_ids_from_request",
               new=AsyncMock(return_value=[_FAKE_ASSET_ID])), \
         patch("src.findings.router.get_session", return_value=_Session([finding])):
        client = TestClient(_make_app())
        resp = client.get("/api/v1/findings/42/advisory")
    assert resp.status_code == 200
    assert resp.json() == {"advisory": None}


def test_get_advisory_returns_brief_with_epss_and_kev_for_scoped_finding():
    finding = _finding(id=42, asset_id=_FAKE_ASSET_ID, detail=_ADVISORY_DETAIL)
    with patch("src.findings.router.require_permission"), \
         patch("src.findings.router.resolve_asset_ids_from_request",
               new=AsyncMock(return_value=[_FAKE_ASSET_ID])), \
         patch("src.findings.router.get_session", return_value=_Session([finding])), \
         patch("src.findings.router.advisory_intel",
               new=AsyncMock(return_value={"epss_percentile": 0.97, "kev": True})):
        client = TestClient(_make_app())
        resp = client.get("/api/v1/findings/42/advisory")
    assert resp.status_code == 200
    adv = resp.json()["advisory"]
    assert adv["advisory_id"] == "GHSA-wr9h-g72x-mwhm"
    assert adv["cve_id"] == "CVE-2025-59425"
    assert adv["cvss_vector"].startswith("CVSS:3.1/")
    assert adv["fixed_version"] == "0.11.0"
    assert adv["epss_percentile"] == 0.97
    assert adv["kev"] is True


# ---------------------------------------------------------------------------
# GET /findings/{id}/report.md  and  /findings/{id}/poc — advisory downloads
# ---------------------------------------------------------------------------

_ADVISORY_DICT = {
    "id": 42, "title": "Pickle RCE on default path", "severity": "high",
    "verdict": "confirmed", "cve": None, "cwe": "CWE-502",
    "repo": "github:acme/example-repo", "exploit_chain": "chain [R1]",
    "evidence": [{"file": "a/x.py", "line": 1, "snippet": "pickle.load(f)", "kind": "sink"}],
    "verification_metadata": {
        "impact": "Arbitrary code execution.",
        "cvss_vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
        "cvss_score": 7.8,
        "poc_script": "print('pwned')", "poc_filename": "poc.py", "poc_language": "python",
    },
}


def test_download_report_returns_markdown_when_in_scope():
    finding = _finding(id=42, asset_id=_FAKE_ASSET_ID)
    with patch("src.findings.router.require_permission"), \
         patch("src.findings.router.resolve_asset_ids_from_request",
               new=AsyncMock(return_value=[_FAKE_ASSET_ID])), \
         patch("src.findings.router.get_session", return_value=_Session([finding])), \
         patch("src.findings.router._finding_to_dict", return_value=dict(_ADVISORY_DICT)):
        client = TestClient(_make_app())
        resp = client.get("/api/v1/findings/42/report.md")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/markdown")
    assert "attachment" in resp.headers["content-disposition"]
    assert resp.text.startswith("# ")
    assert "## Testing & Safe Harbor" in resp.text


def test_download_report_404_when_out_of_scope():
    finding = _finding(id=42, asset_id=_OTHER_ASSET_ID)
    with patch("src.findings.router.require_permission"), \
         patch("src.findings.router.resolve_asset_ids_from_request",
               new=AsyncMock(return_value=[_FAKE_ASSET_ID])), \
         patch("src.findings.router.get_session", return_value=_Session([finding])):
        client = TestClient(_make_app())
        resp = client.get("/api/v1/findings/42/report.md")
    assert resp.status_code == 404


def test_download_poc_returns_attachment_when_in_scope():
    finding = _finding(id=42, asset_id=_FAKE_ASSET_ID)
    with patch("src.findings.router.require_permission"), \
         patch("src.findings.router.resolve_asset_ids_from_request",
               new=AsyncMock(return_value=[_FAKE_ASSET_ID])), \
         patch("src.findings.router.get_session", return_value=_Session([finding])), \
         patch("src.findings.router._finding_to_dict", return_value=dict(_ADVISORY_DICT)):
        client = TestClient(_make_app())
        resp = client.get("/api/v1/findings/42/poc")
    assert resp.status_code == 200
    assert "attachment" in resp.headers["content-disposition"]
    assert "poc.py" in resp.headers["content-disposition"]
    assert "SAFE HARBOR" in resp.text.upper()
    assert "print('pwned')" in resp.text


def test_download_poc_404_when_finding_has_no_poc():
    finding = _finding(id=42, asset_id=_FAKE_ASSET_ID)
    no_poc = dict(_ADVISORY_DICT)
    no_poc["verification_metadata"] = {"impact": "x"}  # no poc_script
    with patch("src.findings.router.require_permission"), \
         patch("src.findings.router.resolve_asset_ids_from_request",
               new=AsyncMock(return_value=[_FAKE_ASSET_ID])), \
         patch("src.findings.router.get_session", return_value=_Session([finding])), \
         patch("src.findings.router._finding_to_dict", return_value=no_poc):
        client = TestClient(_make_app())
        resp = client.get("/api/v1/findings/42/poc")
    assert resp.status_code == 404


def test_download_poc_404_when_out_of_scope():
    finding = _finding(id=42, asset_id=_OTHER_ASSET_ID)
    with patch("src.findings.router.require_permission"), \
         patch("src.findings.router.resolve_asset_ids_from_request",
               new=AsyncMock(return_value=[_FAKE_ASSET_ID])), \
         patch("src.findings.router.get_session", return_value=_Session([finding])):
        client = TestClient(_make_app())
        resp = client.get("/api/v1/findings/42/poc")
    assert resp.status_code == 404


def test_download_report_pdf_returns_pdf_when_in_scope():
    # render_pdf is mocked so WeasyPrint never runs (it segfaults on macOS in
    # tests); the route wiring + scope gating is what this asserts.
    finding = _finding(id=42, asset_id=_FAKE_ASSET_ID)
    with patch("src.findings.router.require_permission"), \
         patch("src.findings.router.resolve_asset_ids_from_request",
               new=AsyncMock(return_value=[_FAKE_ASSET_ID])), \
         patch("src.findings.router.get_session", return_value=_Session([finding])), \
         patch("src.findings.router._finding_to_dict", return_value=dict(_ADVISORY_DICT)), \
         patch("src.findings.router.render_pdf", return_value=b"%PDF-1.7 fake") as rp:
        client = TestClient(_make_app())
        resp = client.get("/api/v1/findings/42/report.pdf")
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "application/pdf"
    assert "attachment" in resp.headers["content-disposition"]
    assert resp.content == b"%PDF-1.7 fake"
    rp.assert_called_once()


def test_download_report_pdf_404_when_out_of_scope():
    finding = _finding(id=42, asset_id=_OTHER_ASSET_ID)
    with patch("src.findings.router.require_permission"), \
         patch("src.findings.router.resolve_asset_ids_from_request",
               new=AsyncMock(return_value=[_FAKE_ASSET_ID])), \
         patch("src.findings.router.get_session", return_value=_Session([finding])):
        client = TestClient(_make_app())
        resp = client.get("/api/v1/findings/42/report.pdf")
    assert resp.status_code == 404


def _llm_cfg(enabled=True):
    cfg = SimpleNamespace(enabled=enabled, api_key="k", api_base_url="https://api.openai.com/v1", model="m")
    return cfg


def test_generate_poc_route_returns_poc_when_in_scope():
    finding = _finding(id=42, asset_id=_FAKE_ASSET_ID)
    poc = {"poc_script": "print('pwned')", "poc_filename": "poc.py", "poc_language": "python"}
    with patch("src.findings.router.require_permission"), \
         patch("src.findings.router.resolve_asset_ids_from_request",
               new=AsyncMock(return_value=[_FAKE_ASSET_ID])), \
         patch("src.findings.router.get_session", return_value=_Session([finding])), \
         patch("src.findings.router._finding_to_dict", return_value=dict(_ADVISORY_DICT)), \
         patch("src.findings.router.fetch_llm_config", return_value=_llm_cfg()), \
         patch("src.findings.router.generate_poc", new=AsyncMock(return_value=poc)), \
         patch("src.findings.router._persist_finding_poc", new=AsyncMock()):
        client = TestClient(_make_app())
        resp = client.post("/api/v1/findings/42/poc/generate")
    assert resp.status_code == 200
    assert resp.json() == {"poc": poc}


def test_generate_poc_route_404_when_out_of_scope():
    finding = _finding(id=42, asset_id=_OTHER_ASSET_ID)
    with patch("src.findings.router.require_permission"), \
         patch("src.findings.router.resolve_asset_ids_from_request",
               new=AsyncMock(return_value=[_FAKE_ASSET_ID])), \
         patch("src.findings.router.get_session", return_value=_Session([finding])):
        client = TestClient(_make_app())
        resp = client.post("/api/v1/findings/42/poc/generate")
    assert resp.status_code == 404


def test_generate_poc_route_409_when_llm_not_configured():
    finding = _finding(id=42, asset_id=_FAKE_ASSET_ID)
    with patch("src.findings.router.require_permission"), \
         patch("src.findings.router.resolve_asset_ids_from_request",
               new=AsyncMock(return_value=[_FAKE_ASSET_ID])), \
         patch("src.findings.router.get_session", return_value=_Session([finding])), \
         patch("src.findings.router._finding_to_dict", return_value=dict(_ADVISORY_DICT)), \
         patch("src.findings.router.fetch_llm_config", return_value=None):
        client = TestClient(_make_app())
        resp = client.post("/api/v1/findings/42/poc/generate")
    assert resp.status_code == 409


def test_generate_poc_route_forwards_instruction():
    finding = _finding(id=42, asset_id=_FAKE_ASSET_ID)
    poc = {"poc_script": "x", "poc_filename": "p.py", "poc_language": "python"}
    gen = AsyncMock(return_value=poc)
    with patch("src.findings.router.require_permission"), \
         patch("src.findings.router.resolve_asset_ids_from_request",
               new=AsyncMock(return_value=[_FAKE_ASSET_ID])), \
         patch("src.findings.router.get_session", return_value=_Session([finding])), \
         patch("src.findings.router._finding_to_dict", return_value=dict(_ADVISORY_DICT)), \
         patch("src.findings.router.fetch_llm_config", return_value=_llm_cfg()), \
         patch("src.findings.router.generate_poc", new=gen), \
         patch("src.findings.router._persist_finding_poc", new=AsyncMock()):
        client = TestClient(_make_app())
        resp = client.post("/api/v1/findings/42/poc/generate", json={"instruction": "use a curl one-liner"})
    assert resp.status_code == 200
    assert gen.await_args.kwargs["instruction"] == "use a curl one-liner"
