"""Unit tests for the globalSearch GraphQL resolver."""
from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from graphql import GraphQLError

from src.search import resolvers as search_resolvers
from src.search.service import SearchHit, SearchResults


def _make_results(grouped=None):
    return SearchResults(
        query="foo",
        total=sum(len(v) for v in (grouped or {}).values()),
        grouped=grouped or {},
        duration_ms=1,
    )


@pytest.mark.asyncio
async def test_global_search_returns_results_for_valid_query(monkeypatch):
    hit = SearchHit(
        type="finding",
        id="42",
        title="CVE-2023-0001",
        subtitle="critical",
        href="/findings?scanner=dependencies_scanning",
        score=0.9,
        metadata={"severity": "critical"},
    )
    fake = MagicMock()
    fake.search.return_value = _make_results({"findings": [hit]})
    monkeypatch.setattr(search_resolvers, "_service", fake)

    result = await search_resolvers.global_search(q="foo")

    fake.search.assert_called_once()
    assert result.total == 1
    assert len(result.findings) == 1
    assert result.findings[0].id == "42"
    assert result.findings[0].title == "CVE-2023-0001"
    assert result.findings[0].metadata == {"severity": "critical"}


@pytest.mark.asyncio
async def test_global_search_rejects_empty_query(monkeypatch):
    monkeypatch.setattr(search_resolvers, "_service", MagicMock())
    with pytest.raises(GraphQLError) as excinfo:
        await search_resolvers.global_search(q="")
    assert excinfo.value.extensions.get("code") == "VALIDATION_ERROR"


@pytest.mark.asyncio
async def test_global_search_rejects_whitespace_query(monkeypatch):
    monkeypatch.setattr(search_resolvers, "_service", MagicMock())
    with pytest.raises(GraphQLError) as excinfo:
        await search_resolvers.global_search(q="   ")
    assert excinfo.value.extensions.get("code") == "VALIDATION_ERROR"


@pytest.mark.asyncio
async def test_global_search_rejects_too_long_query(monkeypatch):
    monkeypatch.setattr(search_resolvers, "_service", MagicMock())
    with pytest.raises(GraphQLError) as excinfo:
        await search_resolvers.global_search(q="a" * 201)
    assert excinfo.value.extensions.get("code") == "VALIDATION_ERROR"


@pytest.mark.asyncio
async def test_global_search_clamps_limit_to_100(monkeypatch):
    fake = MagicMock()
    fake.search.return_value = _make_results()
    monkeypatch.setattr(search_resolvers, "_service", fake)

    await search_resolvers.global_search(q="foo", limit=500)

    assert fake.search.call_args.kwargs["limit"] == 100


@pytest.mark.asyncio
async def test_global_search_rejects_invalid_scope(monkeypatch):
    monkeypatch.setattr(search_resolvers, "_service", MagicMock())
    with pytest.raises(GraphQLError) as excinfo:
        await search_resolvers.global_search(q="foo", scopes=["garbage"])
    assert excinfo.value.extensions.get("code") == "VALIDATION_ERROR"


# ---------------------------------------------------------------------------
# Privileged-scope filtering — audit_events and destinations mirror admin-
# only REST surfaces and must not be reachable through globalSearch for a
# caller without manage_settings, regardless of whether they asked for the
# scope explicitly or implicitly (scopes=None means "everything I can see").
# ---------------------------------------------------------------------------


def _ctx(*, can_manage_settings: bool) -> dict:
    """Build an info_context where has_permission(MANAGE_SETTINGS) returns
    the given verdict. The resolver only reads request.state via has_permission,
    so the SimpleNamespace request is sufficient as a marker."""
    return {"request": SimpleNamespace()}


@pytest.mark.asyncio
async def test_global_search_strips_privileged_scopes_when_no_manage_settings(monkeypatch):
    """Caller asks for ['findings', 'audit_events'] without manage_settings →
    the service only sees ['findings']."""
    fake = MagicMock()
    fake.search.return_value = _make_results({"findings": []})
    monkeypatch.setattr(search_resolvers, "_service", fake)
    monkeypatch.setattr(search_resolvers, "has_permission", lambda req, perm: False)

    await search_resolvers.global_search(
        q="foo",
        scopes=["findings", "audit_events"],
        info_context=_ctx(can_manage_settings=False),
    )

    assert fake.search.call_args.kwargs["scopes"] == ["findings"]


@pytest.mark.asyncio
async def test_global_search_short_circuits_when_only_privileged_requested(monkeypatch):
    """Caller asks for ['audit_events'] without manage_settings → empty
    results, service not called at all (no SQL spent on a forbidden query)."""
    fake = MagicMock()
    monkeypatch.setattr(search_resolvers, "_service", fake)
    monkeypatch.setattr(search_resolvers, "has_permission", lambda req, perm: False)

    result = await search_resolvers.global_search(
        q="foo",
        scopes=["audit_events", "destinations"],
        info_context=_ctx(can_manage_settings=False),
    )

    assert result.total == 0
    assert result.audit_events == []
    assert result.destinations == []
    fake.search.assert_not_called()


@pytest.mark.asyncio
async def test_global_search_defaults_to_public_scopes_when_scopes_none_and_no_manage(monkeypatch):
    """scopes=None ('search everything I can see') defaults to the public
    set only — NOT to the service's VALID_SCOPES, which would include
    audit_events + destinations."""
    fake = MagicMock()
    fake.search.return_value = _make_results()
    monkeypatch.setattr(search_resolvers, "_service", fake)
    monkeypatch.setattr(search_resolvers, "has_permission", lambda req, perm: False)

    await search_resolvers.global_search(
        q="foo",
        scopes=None,
        info_context=_ctx(can_manage_settings=False),
    )

    sent = set(fake.search.call_args.kwargs["scopes"])
    assert "audit_events" not in sent
    assert "destinations" not in sent
    assert {"findings", "repos"}.issubset(sent)


@pytest.mark.asyncio
async def test_global_search_allows_privileged_scopes_when_manage_settings(monkeypatch):
    """A caller with manage_settings can search audit_events and destinations
    — same surface as the equivalent REST endpoints."""
    fake = MagicMock()
    fake.search.return_value = _make_results({"audit_events": [], "destinations": []})
    monkeypatch.setattr(search_resolvers, "_service", fake)
    monkeypatch.setattr(search_resolvers, "has_permission", lambda req, perm: True)

    await search_resolvers.global_search(
        q="foo",
        scopes=["audit_events", "destinations"],
        info_context=_ctx(can_manage_settings=True),
    )

    sent = set(fake.search.call_args.kwargs["scopes"])
    assert sent == {"audit_events", "destinations"}
