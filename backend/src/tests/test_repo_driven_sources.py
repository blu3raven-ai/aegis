"""Store-layer tests for repo-driven (cherry-pick) source connections."""
from __future__ import annotations

import os

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost:5432/test")
os.environ.setdefault("APP_SECRET", "0" * 64)

import pytest  # noqa: E402

from src.sources import store  # noqa: E402
from src.sources import test_connection as tc  # noqa: E402
import src.sources.test_connection as _tc_module  # noqa: E402


def test_create_selected_connection_persists_included_items():
    conn = store.create_connection({
        "category": "code-repositories",
        "sourceType": "github",
        "name": "Cherry-picked",
        "auth": {"token": "ghp_x"},
        "scanScope": "selected",
        "includedItems": ["acme/api", "beta/payments"],
        "connectionMethods": ["pat"],
    })
    assert conn["scanScope"] == "selected"
    assert conn["includedItems"] == ["acme/api", "beta/payments"]


def test_blank_org_connections_do_not_collide():
    store.create_connection({
        "category": "code-repositories", "sourceType": "github",
        "name": "A", "auth": {"token": "ghp_a"},
        "scanScope": "selected", "includedItems": ["acme/api"],
    })
    store.create_connection({
        "category": "code-repositories", "sourceType": "github",
        "name": "B", "auth": {"token": "ghp_b"},
        "scanScope": "selected", "includedItems": ["beta/web"],
    })  # must NOT raise SourceValidationError


# ---------------------------------------------------------------------------
# Task 4: GitHub no-org path sends affiliation=owner,organization_member
# ---------------------------------------------------------------------------

class _FakeResponse:
    def __init__(self, status_code: int, payload: object, headers: dict | None = None) -> None:
        self.status_code = status_code
        self._payload = payload
        self.headers = headers or {}

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            import httpx
            raise httpx.HTTPStatusError("error", request=None, response=self)  # type: ignore[arg-type]

    def json(self) -> object:
        return self._payload


class _MultiResponseClient:
    """Fake httpx.AsyncClient that pops responses from a queue per URL."""

    def __init__(self, responses: dict[str, list[_FakeResponse]], timeout: float = 15) -> None:
        self._responses = responses
        self.timeout = timeout
        self.calls: list[dict] = []

    async def __aenter__(self) -> "_MultiResponseClient":
        return self

    async def __aexit__(self, *_: object) -> None:
        pass

    async def get(self, url: str, *, headers: dict | None = None, params: dict | None = None) -> _FakeResponse:
        self.calls.append({"url": url, "params": params})
        queue = self._responses.get(url, [])
        return queue.pop(0) if queue else _FakeResponse(404, {})


@pytest.mark.asyncio
async def test_github_no_org_sends_affiliation(monkeypatch):
    repos = [
        {"full_name": "acme/api", "archived": False},
        {"full_name": "beta/web", "archived": False},
        {"full_name": "me/dotfiles", "archived": False},
    ]
    client = _MultiResponseClient({
        "https://api.github.com/user": [
            _FakeResponse(200, {"login": "me"}, {"X-OAuth-Scopes": "repo"}),
        ],
        "https://api.github.com/user/repos": [
            _FakeResponse(200, repos),
            _FakeResponse(200, []),  # terminates pagination
        ],
    })
    monkeypatch.setattr(_tc_module.httpx, "AsyncClient", lambda **_kw: client)

    result = await tc.test_connection("github", {"token": "ghp_x"})

    assert result.success is True
    assert set(result.discovered_items) == {"acme/api", "beta/web", "me/dotfiles"}
    # Confirm affiliation param was sent on the repos call
    repos_call = next(c for c in client.calls if "user/repos" in c["url"])
    assert repos_call["params"].get("affiliation") == "owner,organization_member"


# ---------------------------------------------------------------------------
# Task 5: selected-scope dispatch groups by owner; legacy all-scope unchanged
# ---------------------------------------------------------------------------

from unittest.mock import patch  # noqa: E402
from src.sources import triggers  # noqa: E402


def test_selected_scope_dispatches_included_items_per_owner():
    connection = {
        "sourceType": "github", "category": "code-repositories",
        "auth": {"token": "ghp_x", "orgOrOwner": ""},
        "scanScope": "selected",
        "includedItems": ["acme/api", "acme/web", "beta/payments"],
        "discoveredItems": ["acme/api", "acme/web", "beta/payments", "acme/unpicked"],
        "scanners": ["code_scanning"],
    }
    seen = []
    with patch("src.runner.jobs.create_job") as mk, \
         patch("src.runner.jobs.has_active_jobs_for_org", return_value=False), \
         patch("src.storage.create_code_scanning_run"), \
         patch("src.settings.llm.service.build_llm_scan_env", return_value={}):
        mk.side_effect = lambda **kw: seen.append((kw["org"], kw["env_vars"]["GIT_REPOS"]))
        triggers.dispatch_source_scan(connection)
    owners = {org for org, _ in seen}
    assert owners == {"acme", "beta"}
    acme_repos = next(repos for org, repos in seen if org == "acme")
    assert "unpicked" not in acme_repos  # only included items scanned


def test_legacy_all_scope_still_dispatches_discovered_items():
    connection = {
        "sourceType": "github", "category": "code-repositories",
        "auth": {"token": "ghp_x", "orgOrOwner": "acme"},
        "scanScope": "all",
        "discoveredItems": ["acme/api"],
        "scanners": ["code_scanning"],
    }
    seen = []
    with patch("src.runner.jobs.create_job") as mk, \
         patch("src.runner.jobs.has_active_jobs_for_org", return_value=False), \
         patch("src.storage.create_code_scanning_run"), \
         patch("src.settings.llm.service.build_llm_scan_env", return_value={}):
        mk.side_effect = lambda **kw: seen.append((kw["org"], kw["env_vars"]["GIT_REPOS"]))
        triggers.dispatch_source_scan(connection)
    assert {org for org, _ in seen} == {"acme"}


# ---------------------------------------------------------------------------
# Task 9: sources-list finding counts aggregate across cherry-pick owners
# ---------------------------------------------------------------------------

import datetime  # noqa: E402
import secrets  # noqa: E402
import uuid  # noqa: E402

from sqlalchemy import delete as _sa_delete  # noqa: E402

from src.db.models import Asset, Finding, SourceConnection  # noqa: E402


@pytest.mark.asyncio
async def test_selected_scope_aggregates_finding_counts(db_session):
    """list_connections returns aggregated findingCounts for a cherry-pick connection."""
    conn_id = f"src_{secrets.token_hex(8)}"
    asset_id = str(uuid.uuid4())
    now = datetime.datetime.now(datetime.timezone.utc)

    # Cherry-pick connection: blank orgOrOwner, includedItems lists the repo.
    db_session.add(SourceConnection(
        id=conn_id,
        category="code-repositories",
        source_type="github",
        name="acme cherry-pick",
        auth={"orgOrOwner": "", "token": "x"},
        scan_scope="selected",
        excluded_items=[],
        included_items=["acme/api"],
        scanners=[],
        connection_methods=["pat"],
        sync_schedule="6h",
        scan_auto_enabled=False,
        scan_schedule_preset="6h",
        status="not-synced",
        org_id="default",
        created_at=now,
        updated_at=now,
    ))
    db_session.add(Asset(
        id=asset_id,
        type="repo",
        source="source_connection",
        external_ref="github:acme/api",
        display_name="acme/api",
    ))
    db_session.add(Finding(
        tool="code_scanning",
        identity_key=f"k-{uuid.uuid4()}",
        asset_id=asset_id,
        state="open",
        severity="critical",
    ))
    await db_session.commit()

    try:
        result = store.list_connections()
        match = next((d for d in result if d["id"] == conn_id), None)
        assert match is not None, "connection missing from list_connections result"
        counts = match["findingCounts"]
        assert counts["critical"] == 1, f"expected critical=1, got {counts}"
        assert counts["high"] == 0
        assert counts["medium"] == 0
        assert counts["low"] == 0
    finally:
        await db_session.execute(_sa_delete(Finding).where(Finding.asset_id == asset_id))
        await db_session.execute(_sa_delete(Asset).where(Asset.id == asset_id))
        await db_session.execute(_sa_delete(SourceConnection).where(SourceConnection.id == conn_id))
        await db_session.commit()
