"""Enrichment admin endpoints — advisory mirror lifecycle and per-scanner source config.

This router groups two related ops surfaces:

  * Mirror lifecycle — refresh/reconcile for centrally cached advisory feeds
    (OSV, EPSS, and future KEV/GHSA mirrors). Each spawns background work and
    returns immediately so the caller does not block on a long-running fetch.
  * Source config — credential moves between scanners (NVD / GHSA / Argus per
    tool), where the credentials live in app_config and never leave the server.

All endpoints are gated on MANAGE_SETTINGS.
"""
from __future__ import annotations

import asyncio
import logging
import threading
from datetime import datetime, timedelta, timezone

import sqlalchemy as sa
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import JSONResponse

from src.authz.enforcement.dependencies import Permission
from src.authz.permissions.catalog import MANAGE_SETTINGS
from src.db.engine import get_session
from src.db.models import EpssScore, KevEntry, OsvAdvisory, OsvRefreshRun
from src.shared.config import read_app_config, write_app_config

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/enrichment", tags=["enrichment"])

_VALID_RECONCILE_MODES = {"incremental", "full"}
_VALID_ADVISORY_TOOLS = {"dependencies_scanning", "container_scanning"}
_ADVISORY_KEYS = ("nvdEnabled", "nvdApiKey", "ghsaEnabled", "ghsaApiKey")


def _spawn_osv_refresh() -> None:
    def _run() -> None:
        try:
            from src.jobs.osv_refresh import refresh_osv_catalog
            result = refresh_osv_catalog()
            logger.info("osv refresh complete: %s", result)
        except Exception:
            logger.exception("osv refresh failed")

    threading.Thread(target=_run, daemon=True, name="osv-refresh-ondemand").start()


def _spawn_osv_reconcile(mode: str) -> None:
    def _run() -> None:
        try:
            from src.osv.rematch import reconcile_sbom_matches
            from src.osv.store import OsvStore

            store = OsvStore()
            if mode == "full":
                ids = asyncio.run(store.list_changed_since(
                    datetime(1970, 1, 1, tzinfo=timezone.utc)
                ))
            else:
                ids = asyncio.run(store.list_changed_since(
                    datetime.now(timezone.utc) - timedelta(days=1)
                ))
            count = asyncio.run(reconcile_sbom_matches(ids))
            logger.info("osv reconcile (%s) complete: %d findings", mode, count)
        except Exception:
            logger.exception("osv reconcile failed")

    threading.Thread(target=_run, daemon=True, name=f"osv-reconcile-{mode}").start()


def _iso(value) -> str | None:
    return value.isoformat() if value is not None else None


@router.get("/status")
async def get_enrichment_status(
    request: Request,
    _: None = Depends(Permission(MANAGE_SETTINGS)),
) -> JSONResponse:
    """Freshness + size of each advisory feed the mirror serves.

    Backs the settings "Advisory Data" card so an admin can see whether the
    OSV/EPSS/KEV mirrors have ever been populated (matching produces zero
    findings until OSV has run at least once) and when they last refreshed.
    """
    async with get_session() as session:
        last_osv = (
            await session.execute(
                sa.select(OsvRefreshRun).order_by(OsvRefreshRun.started_at.desc()).limit(1)
            )
        ).scalar_one_or_none()
        osv_count = await session.scalar(sa.select(sa.func.count()).select_from(OsvAdvisory))
        epss_count = await session.scalar(sa.select(sa.func.count()).select_from(EpssScore))
        epss_fetched = await session.scalar(sa.select(sa.func.max(EpssScore.fetched_at)))
        kev_count = await session.scalar(sa.select(sa.func.count()).select_from(KevEntry))
        kev_ingested = await session.scalar(sa.select(sa.func.max(KevEntry.ingested_at)))

    return JSONResponse(
        {
            "osv": {
                "advisories": osv_count or 0,
                "lastRefreshedAt": _iso(last_osv.finished_at) if last_osv else None,
                "startedAt": _iso(last_osv.started_at) if last_osv else None,
                "error": last_osv.error if last_osv else None,
            },
            "epss": {"scores": epss_count or 0, "lastRefreshedAt": _iso(epss_fetched)},
            "kev": {"entries": kev_count or 0, "lastRefreshedAt": _iso(kev_ingested)},
        }
    )


@router.post("/osv/refresh", status_code=202)
def post_osv_refresh(
    request: Request,
    _: None = Depends(Permission(MANAGE_SETTINGS)),
) -> JSONResponse:
    _spawn_osv_refresh()
    return JSONResponse(status_code=202, content={"status": "refresh dispatched"})


@router.post("/osv/reconcile", status_code=202)
def post_osv_reconcile(
    request: Request,
    mode: str = Query(default="incremental"),
    _: None = Depends(Permission(MANAGE_SETTINGS)),
) -> JSONResponse:
    if mode not in _VALID_RECONCILE_MODES:
        raise HTTPException(
            status_code=400,
            detail=f"mode must be one of {sorted(_VALID_RECONCILE_MODES)}, got {mode!r}",
        )
    _spawn_osv_reconcile(mode)
    return JSONResponse(status_code=202, content={"status": f"reconcile ({mode}) dispatched"})


@router.post("/epss/refresh")
def post_epss_refresh(
    request: Request,
    _: None = Depends(Permission(MANAGE_SETTINGS)),
) -> JSONResponse:
    """Trigger an immediate EPSS feed fetch + upsert.

    Fetch failures bubble up as 502 so the caller can decide to retry.
    """
    from src.jobs.epss_refresh import refresh_epss_scores

    try:
        result = refresh_epss_scores()
    except Exception as exc:
        logger.exception("epss refresh failed")
        raise HTTPException(status_code=502, detail=f"EPSS refresh failed: {exc}") from exc

    return JSONResponse(result)


@router.post("/advisory-sources/copy")
async def copy_advisory_sources(
    request: Request,
    _: None = Depends(Permission(MANAGE_SETTINGS)),
) -> JSONResponse:
    """Copy NVD + GHSA credentials from one scanner tool to another.

    Credentials stay server-side; the response only confirms the copy.
    """
    body = await request.json()
    source = body.get("source", "")
    target = body.get("target", "")

    if source not in _VALID_ADVISORY_TOOLS or target not in _VALID_ADVISORY_TOOLS:
        raise HTTPException(
            status_code=400,
            detail=f"source and target must be one of {sorted(_VALID_ADVISORY_TOOLS)}",
        )
    if source == target:
        raise HTTPException(status_code=400, detail="source and target must be different tools")

    config = read_app_config()
    tools = config.get("tools", {})
    source_config = tools.get(source, {})

    if not source_config.get("nvdEnabled") and not source_config.get("ghsaEnabled"):
        raise HTTPException(
            status_code=400,
            detail=f"No advisory sources configured in {source}",
        )

    target_config = tools.setdefault(target, {})
    for key in _ADVISORY_KEYS:
        if key in source_config:
            target_config[key] = source_config[key]

    write_app_config(config, event_type="settings.advisory_sources_copied")
    return JSONResponse({"ok": True, "message": f"Advisory sources copied from {source} to {target}"})
