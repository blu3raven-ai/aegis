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
