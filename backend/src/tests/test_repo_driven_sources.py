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
