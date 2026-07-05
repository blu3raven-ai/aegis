import pytest

from src.shared import github
from src.shared.github import GitHubApiError


class _FakeResponse:
    def __init__(self, status_code: int, payload: object, text: str = "", headers: dict[str, str] | None = None) -> None:
        self.status_code = status_code
        self._payload = payload
        self.text = text
        self.headers = headers or {}

    def json(self) -> object:
        return self._payload


class _FakeAsyncClient:
    response: _FakeResponse
    last_request: dict[str, object] | None = None

    def __init__(self, timeout: float = 30.0) -> None:
        self.timeout = timeout

    async def __aenter__(self) -> "_FakeAsyncClient":
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        return None

    async def get(self, url: str, headers: dict[str, str] | None = None, params: dict[str, str] | None = None) -> _FakeResponse:
        _FakeAsyncClient.last_request = {
            "url": url,
            "headers": headers,
            "params": params,
            "timeout": self.timeout,
        }
        return _FakeAsyncClient.response


@pytest.mark.asyncio
async def test_fetch_org_teams(monkeypatch):
    teams_payload = [
        {"id": 1, "name": "Team A", "slug": "team-a"},
        {"id": 2, "name": "Team B", "slug": "team-b"},
    ]
    _FakeAsyncClient.response = _FakeResponse(200, teams_payload)
    _FakeAsyncClient.last_request = None
    monkeypatch.setattr(github.httpx, "AsyncClient", _FakeAsyncClient)
    monkeypatch.setenv("GITHUB_API_URL", "https://api.github.com")

    teams = await github.fetch_org_teams("my-org", "token-123")

    assert teams == teams_payload
    assert _FakeAsyncClient.last_request["url"] == "https://api.github.com/orgs/my-org/teams"
    assert _FakeAsyncClient.last_request["headers"]["Authorization"] == "Bearer token-123"
    assert _FakeAsyncClient.last_request["params"] == {"per_page": "100"}


@pytest.mark.asyncio
async def test_fetch_team_members(monkeypatch):
    members_payload = [
        {"id": 101, "login": "user1"},
        {"id": 102, "login": "user2"},
    ]
    _FakeAsyncClient.response = _FakeResponse(200, members_payload)
    _FakeAsyncClient.last_request = None
    monkeypatch.setattr(github.httpx, "AsyncClient", _FakeAsyncClient)
    monkeypatch.setenv("GITHUB_API_URL", "https://api.github.com")

    members = await github.fetch_team_members("my-org", "team-a", "token-123")

    assert members == members_payload
    assert _FakeAsyncClient.last_request["url"] == "https://api.github.com/orgs/my-org/teams/team-a/members"
    assert _FakeAsyncClient.last_request["headers"]["Authorization"] == "Bearer token-123"
    assert _FakeAsyncClient.last_request["params"] == {"per_page": "100"}


@pytest.mark.asyncio
async def test_fetch_team_repositories(monkeypatch):
    repos_payload = [
        {"id": 201, "name": "repo1"},
        {"id": 202, "name": "repo2"},
    ]
    _FakeAsyncClient.response = _FakeResponse(200, repos_payload)
    _FakeAsyncClient.last_request = None
    monkeypatch.setattr(github.httpx, "AsyncClient", _FakeAsyncClient)
    monkeypatch.setenv("GITHUB_API_URL", "https://api.github.com")

    repos = await github.fetch_team_repositories("my-org", "team-a", "token-123")

    assert repos == repos_payload
    assert _FakeAsyncClient.last_request["url"] == "https://api.github.com/orgs/my-org/teams/team-a/repos"
    assert _FakeAsyncClient.last_request["headers"]["Authorization"] == "Bearer token-123"
    assert _FakeAsyncClient.last_request["params"] == {"per_page": "100"}


@pytest.mark.asyncio
async def test_fetch_rate_limit_returns_core_resource(monkeypatch):
    _FakeAsyncClient.response = _FakeResponse(
        200,
        {
            "resources": {
                "core": {
                    "limit": 5000,
                    "remaining": 4999,
                    "reset": 1710000000,
                    "used": 1,
                }
            }
        },
    )
    _FakeAsyncClient.last_request = None
    monkeypatch.setattr(github.httpx, "AsyncClient", _FakeAsyncClient)
    monkeypatch.setenv("GITHUB_API_URL", "https://example.github.invalid/api")

    core = await github.fetch_rate_limit("token-123")

    assert core == {
        "limit": 5000,
        "remaining": 4999,
        "reset": 1710000000,
        "used": 1,
    }
    assert _FakeAsyncClient.last_request == {
        "url": "https://example.github.invalid/api/rate_limit",
        "headers": {
            "Authorization": "Bearer token-123",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        },
        "params": None,
        "timeout": github.TIMEOUT_SECONDS,
    }


@pytest.mark.asyncio
async def test_fetch_rate_limit_raises_on_unexpected_shape(monkeypatch):
    _FakeAsyncClient.response = _FakeResponse(200, {"resources": {}})
    monkeypatch.setattr(github.httpx, "AsyncClient", _FakeAsyncClient)
    monkeypatch.setenv("GITHUB_API_URL", "https://api.github.com")

    with pytest.raises(GitHubApiError) as exc_info:
        await github.fetch_rate_limit("token-123")

    assert exc_info.value.status == 502


@pytest.mark.asyncio
async def test_check_token_permissions_full_access(monkeypatch):
    responses = [
        _FakeResponse(200, []), # fetch_org_teams (read_org)
        _FakeResponse(200, [{"name": "repo1"}]), # fetch_org_repos
        _FakeResponse(200, []), # fetch_repo_collaborators (repo_push)
    ]
    
    request_idx = 0
    async def fake_get(self, url: str, **kwargs):
        nonlocal request_idx
        res = responses[request_idx]
        request_idx += 1
        return res

    monkeypatch.setattr(_FakeAsyncClient, "get", fake_get)
    monkeypatch.setattr(github.httpx, "AsyncClient", _FakeAsyncClient)
    monkeypatch.setenv("GITHUB_API_URL", "https://api.github.com")

    results = await github.check_token_permissions("my-org", "token-123")
    assert results["read_org"] is True
    assert results["repo_access"] is True
    assert results["repo_push"] is True
    assert results["capabilities"]["direct_collaborator_sync"] is True

@pytest.mark.asyncio
async def test_check_token_permissions_no_push(monkeypatch):
    responses = [
        _FakeResponse(200, []), # fetch_org_teams (read_org)
        _FakeResponse(200, [{"name": "repo1"}]), # fetch_org_repos
        _FakeResponse(403, {"message": "Forbidden"}), # fetch_repo_collaborators (repo_push FAIL)
    ]
    
    request_idx = 0
    async def fake_get(self, url: str, **kwargs):
        nonlocal request_idx
        res = responses[request_idx]
        request_idx += 1
        return res

    monkeypatch.setattr(_FakeAsyncClient, "get", fake_get)
    monkeypatch.setattr(github.httpx, "AsyncClient", _FakeAsyncClient)
    monkeypatch.setenv("GITHUB_API_URL", "https://api.github.com")

    results = await github.check_token_permissions("my-org", "token-123")
    assert results["read_org"] is True
    assert results["repo_access"] is True
    assert results["repo_push"] is False
    assert results["capabilities"]["direct_collaborator_sync"] is False

@pytest.mark.asyncio
async def test_check_token_permissions_no_org_access(monkeypatch):
    # If we can't even list teams, we likely don't have read:org
    responses = [
        _FakeResponse(403, {"message": "Forbidden"}), # fetch_org_teams FAIL
        _FakeResponse(200, [{"name": "repo1"}]), # fetch_org_repos
        _FakeResponse(200, []), # fetch_repo_collaborators
    ]
    
    request_idx = 0
    async def fake_get(self, url: str, **kwargs):
        nonlocal request_idx
        res = responses[request_idx]
        request_idx += 1
        return res

    monkeypatch.setattr(_FakeAsyncClient, "get", fake_get)
    monkeypatch.setattr(github.httpx, "AsyncClient", _FakeAsyncClient)
    monkeypatch.setenv("GITHUB_API_URL", "https://api.github.com")

    results = await github.check_token_permissions("my-org", "token-123")
    assert results["read_org"] is False
    assert results["repo_access"] is True
    assert results["repo_push"] is True
    assert results["capabilities"]["direct_collaborator_sync"] is True

@pytest.mark.asyncio
async def test_check_token_permissions_empty_org(monkeypatch):
    responses = [
        _FakeResponse(200, []), # fetch_org_teams
        _FakeResponse(200, []), # fetch_org_repos (EMPTY)
    ]
    
    request_idx = 0
    async def fake_get(self, url: str, **kwargs):
        nonlocal request_idx
        res = responses[request_idx]
        request_idx += 1
        return res

    monkeypatch.setattr(_FakeAsyncClient, "get", fake_get)
    monkeypatch.setattr(github.httpx, "AsyncClient", _FakeAsyncClient)
    monkeypatch.setenv("GITHUB_API_URL", "https://api.github.com")

    results = await github.check_token_permissions("my-org", "token-123")
    # If no repos, we can't verify push, so we assume True if we could list repos
    assert results["read_org"] is True
    assert results["repo_access"] is True
    assert results["repo_push"] is True
    assert results["capabilities"]["direct_collaborator_sync"] is True

@pytest.mark.asyncio
async def test_check_token_permissions_no_push_marks_optional_collaborator_sync(monkeypatch):
    responses = [
        _FakeResponse(200, []), # fetch_org_teams (read_org)
        _FakeResponse(200, [{"name": "repo1"}]), # fetch_org_repos
        _FakeResponse(403, {"message": "Forbidden"}), # fetch_repo_collaborators (repo_push FAIL)
    ]
    
    request_idx = 0
    async def fake_get(self, url: str, **kwargs):
        nonlocal request_idx
        res = responses[request_idx]
        request_idx += 1
        return res

    monkeypatch.setattr(_FakeAsyncClient, "get", fake_get)
    monkeypatch.setattr(github.httpx, "AsyncClient", _FakeAsyncClient)
    monkeypatch.setenv("GITHUB_API_URL", "https://api.github.com")

    results = await github.check_token_permissions("my-org", "token-123")
    assert results["read_org"] is True
    assert results["repo_access"] is True
    assert results["repo_push"] is False
    assert results["capabilities"]["direct_collaborator_sync"] is False
