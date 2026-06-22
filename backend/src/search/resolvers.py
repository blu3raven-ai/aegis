"""Resolver for the cross-domain global search field.

The search service exposes four scopes — ``findings``, ``repos``,
``audit_events``, ``destinations``. The first two are visible to anyone
with ``view_findings``; the last two mirror admin-only REST surfaces
(audit log, notification destinations admin) and are gated on
``manage_settings`` here as well so the GraphQL field cannot bypass the
REST permission boundary.

Filtering is silent: a non-admin caller who asks for
``scopes=["audit_events"]`` receives an empty ``audit_events`` list (and
no other scope is searched) rather than 403, so the existence of the
admin surface is not advertised to a probing viewer.
"""
from __future__ import annotations

from typing import Optional

import strawberry
from graphql import GraphQLError

from src.authz.enforcement import has_permission
from src.authz.permissions.catalog import MANAGE_SETTINGS
from src.search.service import SearchService, VALID_SCOPES


_service = SearchService()

# Scopes whose REST counterparts require manage_settings. Kept in sync with
# the gates on /api/v1/settings/audit/* and /api/v1/notifications/destinations*.
_PRIVILEGED_SCOPES = frozenset({"audit_events", "destinations"})
_PUBLIC_SCOPES = VALID_SCOPES - _PRIVILEGED_SCOPES


@strawberry.type
class SearchHit:
    type: str
    id: str
    title: str
    subtitle: str
    href: str
    score: float
    metadata: strawberry.scalars.JSON


@strawberry.type
class SearchResults:
    query: str
    total: int
    duration_ms: int
    findings: list[SearchHit]
    repos: list[SearchHit]
    audit_events: list[SearchHit]
    destinations: list[SearchHit]


_Q_MIN = 1
_Q_MAX = 200
_LIMIT_MAX = 100


def _empty_results(query: str) -> SearchResults:
    return SearchResults(
        query=query,
        total=0,
        duration_ms=0,
        findings=[],
        repos=[],
        audit_events=[],
        destinations=[],
    )


async def global_search(
    *,
    q: str,
    scopes: Optional[list[str]] = None,
    limit: int = 50,
    org_id: Optional[str] = None,
    asset_ids: Optional[list[str]] = None,
    info_context: Optional[dict] = None,
) -> SearchResults:
    q = (q or "").strip()
    if len(q) < _Q_MIN:
        raise GraphQLError(
            "Query must not be empty",
            extensions={"code": "VALIDATION_ERROR"},
        )
    if len(q) > _Q_MAX:
        raise GraphQLError(
            f"Query exceeds {_Q_MAX} characters",
            extensions={"code": "VALIDATION_ERROR"},
        )

    limit = max(1, min(_LIMIT_MAX, limit))

    if scopes is not None:
        invalid = [s for s in scopes if s not in VALID_SCOPES]
        if invalid:
            raise GraphQLError(
                f"Unknown scope(s): {', '.join(invalid)}. Valid: {sorted(VALID_SCOPES)}",
                extensions={"code": "VALIDATION_ERROR"},
            )

    # Permission-aware scope filtering. Callers without manage_settings cannot
    # search audit_events or destinations via this field — those scopes mirror
    # admin-only REST surfaces and must not be reachable through GraphQL.
    # info_context is optional only so unit tests of the resolver function in
    # isolation don't need to construct a full request; the schema.py call
    # site always passes it.
    request = (info_context or {}).get("request")
    can_see_privileged = request is not None and has_permission(request, MANAGE_SETTINGS)
    allowed = VALID_SCOPES if can_see_privileged else _PUBLIC_SCOPES
    if scopes is not None:
        effective_scopes: Optional[list[str]] = [s for s in scopes if s in allowed]
        if not effective_scopes:
            # Caller asked exclusively for scopes they cannot see — short
            # circuit so we don't spin up a SQL query just to discard it.
            return _empty_results(q)
    else:
        # scopes=None means "search everything I can see"; expand to the
        # explicit allowed set so the service doesn't fall back to its own
        # VALID_SCOPES default (which includes audit_events + destinations).
        effective_scopes = sorted(allowed)

    results = _service.search(
        q,
        scopes=effective_scopes,
        org_id=org_id,
        asset_ids=asset_ids,
        limit=limit,
    )

    def _hit(hit) -> SearchHit:
        return SearchHit(
            type=hit.type,
            id=hit.id,
            title=hit.title,
            subtitle=hit.subtitle or "",
            href=hit.href,
            score=hit.score,
            metadata=hit.metadata or {},
        )

    grouped = results.grouped
    return SearchResults(
        query=results.query,
        total=results.total,
        duration_ms=results.duration_ms,
        findings=[_hit(h) for h in grouped.get("findings", [])],
        repos=[_hit(h) for h in grouped.get("repos", [])],
        audit_events=[_hit(h) for h in grouped.get("audit_events", [])],
        destinations=[_hit(h) for h in grouped.get("destinations", [])],
    )
