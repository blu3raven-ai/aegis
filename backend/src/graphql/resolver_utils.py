"""Shared utilities for scanner GraphQL resolvers."""
from __future__ import annotations

import math
import time
from typing import Any, Callable, NoReturn, Sequence

from graphql import GraphQLError

from src.shared.paths import parse_iso_utc

AGE_RANGES: dict[str, tuple[int, int]] = {
    "< 7d": (0, 7),
    "7-30d": (7, 30),
    "1-3mo": (30, 90),
    "3-6mo": (90, 180),
    "6mo+": (180, 999999),
}

CVSS_RANGES: dict[str, tuple[float, float]] = {
    "9.0+": (9.0, 10.1),
    "7.0-8.9": (7.0, 9.0),
    "4.0-6.9": (4.0, 7.0),
    "0.1-3.9": (0.1, 4.0),
}


def raise_unauthenticated(msg: str = "Unauthorized") -> NoReturn:
    raise GraphQLError(msg, extensions={"code": "UNAUTHENTICATED"})


def raise_permission_denied(msg: str = "Permission denied") -> NoReturn:
    raise GraphQLError(msg, extensions={"code": "PERMISSION_DENIED"})


def raise_bad_input(msg: str) -> NoReturn:
    raise GraphQLError(msg, extensions={"code": "BAD_USER_INPUT"})


def _git_repos_only(sources: list) -> list[dict[str, Any]]:
    """Extract only git repos (not container images) from scan sources."""
    repos: dict[str, dict[str, Any]] = {}
    for s in sources:
        for url in s.repo_urls:
            parts = url.rstrip("/").removesuffix(".git").split("/")[-2:]
            full_name = "/".join(parts)
            if full_name not in repos:
                repos[full_name] = {"full_name": full_name, "name": parts[-1]}
    return list(repos.values())


def load_cached_findings(
    asset_ids: list[str],
    ctx: dict[str, Any] | None,
    cache_key_prefix: str,
    storage_fn: Callable[..., list[dict[str, Any]] | None],
) -> list[dict[str, Any]]:
    """Load findings with per-request caching, scoped by asset_ids."""
    if not ctx:
        raise_unauthenticated()
    if not asset_ids:
        return []
    request_cache = ctx.get("_cache")
    cache_key = f"{cache_key_prefix}:{','.join(sorted(asset_ids))}"
    if request_cache is not None and cache_key in request_cache:
        return list(request_cache[cache_key])
    findings = storage_fn(asset_ids=asset_ids) or []
    if request_cache is not None:
        request_cache[cache_key] = findings
    return findings


def paginate(
    items: list[dict[str, Any]],
    page: int,
    per_page: int,
) -> tuple[list[dict[str, Any]], int, int]:
    """Slice `items` for the requested page. Returns (page_items, total_pages, clamped_page)."""
    total_pages = max(1, math.ceil(len(items) / per_page))
    page = max(1, min(page, total_pages))
    start = (page - 1) * per_page
    return items[start:start + per_page], total_pages, page


def filter_by_age_bucket(
    findings: list[dict[str, Any]],
    age_bucket: str | None,
    date_keys: Sequence[str],
) -> list[dict[str, Any]]:
    """Keep findings whose first matching date key falls in the AGE_RANGES bucket."""
    if not age_bucket:
        return findings
    normalized = age_bucket.replace("–", "-")
    bounds = AGE_RANGES.get(normalized)
    if not bounds:
        return findings
    lo, hi = bounds
    now_s = time.time()

    def _age_days(f: dict[str, Any]) -> float:
        for key in date_keys:
            v = f.get(key)
            if v:
                try:
                    return (now_s - parse_iso_utc(v).timestamp()) / 86400
                except (ValueError, OSError):
                    return 0
        return 0

    return [f for f in findings if lo <= _age_days(f) < hi]


def filter_by_search(
    findings: list[dict[str, Any]],
    query: str | None,
    fields_fn: Callable[[dict[str, Any]], Sequence[str | None]],
) -> list[dict[str, Any]]:
    """Keep findings where any string returned by `fields_fn(f)` contains `query` (case-insensitive)."""
    if not query:
        return findings
    q = query.lower()
    return [
        f for f in findings
        if any(q in (v or "").lower() for v in fields_fn(f))
    ]


def filter_by_csv_org(
    findings: list[dict[str, Any]],
    org: str | None,
    org_fn: Callable[[dict[str, Any]], str | None],
) -> list[dict[str, Any]]:
    """Keep findings whose `org_fn(f)` matches any comma-separated org in `org` (case-insensitive)."""
    if not org:
        return findings
    wanted = {o.strip().lower() for o in org.split(",") if o.strip()}
    if not wanted:
        return findings
    return [f for f in findings if (org_fn(f) or "").lower() in wanted]


async def unpack_ctx(info: Any) -> tuple[dict[str, Any], list[str]]:
    """Resolve the GraphQL request context and pull out `asset_ids`.

    Every Query/Mutation method needs the same two values: the auth context
    and the scoped asset_ids list. Inlining this in every resolver duplicates
    the literal strings `"request"` and `"asset_ids"` 80+ times across schema.py.

    Returns: (ctx, asset_ids). Empty list when the viewer has no scope.
    """
    from src.graphql.auth import get_graphql_context
    ctx = await get_graphql_context(info.context["request"])
    return ctx, ctx.get("asset_ids") or []
