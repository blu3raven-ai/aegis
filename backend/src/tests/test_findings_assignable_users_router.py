"""Tests for GET /api/v1/findings/assignable-users."""
from __future__ import annotations

import os
from unittest.mock import AsyncMock, patch

from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost:5432/test")
os.environ.setdefault("APP_SECRET", "0" * 64)

from src.authz.enforcement.dependencies import Permission  # noqa: E402
from src.authz.permissions.catalog import REVIEW_FINDINGS  # noqa: E402
from src.findings.router import router as findings_router  # noqa: E402
from src.findings.service import MAX_ASSIGNABLE_USERS_LIMIT  # noqa: E402

_VIEW_PERMS = {"review_findings"}
_NO_PERMS: set[str] = set()


def _make_app(*, allow_review_findings: bool = True) -> FastAPI:
    app = FastAPI()
    app.include_router(findings_router)

    @app.middleware("http")
    async def inject_user(request: Request, call_next):
        request.state.user_sub = "viewer-1"
        request.state.user_role = "viewer"
        request.state.user_role_id = None
        return await call_next(request)

    if allow_review_findings:
        app.dependency_overrides[Permission(REVIEW_FINDINGS)] = lambda: None
    return app


def test_get_assignable_users_returns_envelope_with_user_rows():
    seeded = [
        {"id": "u-1", "username": "alice", "email": "alice@example.test"},
        {"id": "u-2", "username": "bob", "email": "bob@example.test"},
    ]
    with (
        patch(
            "src.findings.router.get_session",
            return_value=_NullSession(),
        ),
        patch(
            "src.findings.router.list_assignable_users",
            new=AsyncMock(return_value=seeded),
        ) as mock_list,
    ):
        client = TestClient(_make_app())
        resp = client.get("/api/v1/findings/assignable-users")

    assert resp.status_code == 200
    assert resp.json() == {"users": seeded}
    mock_list.assert_awaited_once()
    assert mock_list.await_args.kwargs == {"q": None, "limit": 20}


def test_get_assignable_users_forwards_q_filter_to_service():
    with (
        patch(
            "src.findings.router.get_session",
            return_value=_NullSession(),
        ),
        patch(
            "src.findings.router.list_assignable_users",
            new=AsyncMock(return_value=[]),
        ) as mock_list,
    ):
        client = TestClient(_make_app())
        resp = client.get("/api/v1/findings/assignable-users?q=ali&limit=5")

    assert resp.status_code == 200
    assert resp.json() == {"users": []}
    assert mock_list.await_args.kwargs == {"q": "ali", "limit": 5}


def test_get_assignable_users_passes_oversized_limit_unmodified_for_service_clamping():
    captured: dict[str, object] = {}

    async def fake_list_assignable_users(session, *, q, limit):
        captured["q"] = q
        captured["limit"] = limit
        # Mimic the real service capping the response at MAX_ASSIGNABLE_USERS_LIMIT
        # so we can assert the handler never returns more than that.
        return [
            {"id": f"u-{i}", "username": f"user-{i}", "email": f"u{i}@example.test"}
            for i in range(MAX_ASSIGNABLE_USERS_LIMIT)
        ]

    with (
        patch(
            "src.findings.router.get_session",
            return_value=_NullSession(),
        ),
        patch(
            "src.findings.router.list_assignable_users",
            new=fake_list_assignable_users,
        ),
    ):
        client = TestClient(_make_app())
        resp = client.get("/api/v1/findings/assignable-users?limit=9999")

    assert resp.status_code == 200
    # Handler must forward the raw limit so the service is the single source of
    # truth for clamping — double-clamping would mask a regression there.
    assert captured["limit"] == 9999
    assert len(resp.json()["users"]) == MAX_ASSIGNABLE_USERS_LIMIT


def test_get_assignable_users_rejects_caller_without_review_findings_with_403():
    with (
        patch(
            "src.authz.enforcement.dependencies.has_role_permission",
            return_value=False,
        ),
        patch(
            "src.findings.router.list_assignable_users",
            new=AsyncMock(),
        ) as mock_list,
    ):
        client = TestClient(_make_app(allow_review_findings=False))
        resp = client.get("/api/v1/findings/assignable-users")

    assert resp.status_code == 403
    mock_list.assert_not_called()


class _NullSession:
    """Stand-in async context manager so the handler can `async with get_session()`."""

    async def __aenter__(self):
        return None

    async def __aexit__(self, *args):
        return None
