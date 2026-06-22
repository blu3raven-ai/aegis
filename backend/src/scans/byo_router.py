"""Bring-Your-Own scanner result import.

Accepts a batch of targets + findings from an out-of-band scanner (Trivy, Snyk,
etc.). Upserts each target as an asset, then ingests findings against those
assets deduped via uq_finding_tool_asset_key.
"""
from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from src.assets.grants import auto_grant_to_uploader
from src.assets.refs import image_ref, repo_ref
from src.assets.service import upsert_asset
from src.audit_log.decorators import audited
from src.authz.enforcement.dependencies import Permission
from src.authz.permissions.catalog import MANAGE_SOURCES, RUN_SCANS
from src.db.engine import async_session_factory
from src.db.models import Finding
from src.scans.service import record_byo_scan_run


router = APIRouter(prefix="/api/v1/scans", tags=["scans"])


async def _db():
    async with async_session_factory() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise


def _user_id(request: Request) -> str:
    user_id = getattr(request.state, "user_sub", None)
    if not user_id:
        raise HTTPException(status_code=401, detail="unauthorized")
    return user_id


class ByoTargetRepo(BaseModel):
    type: Literal["repo"]
    source_type: str
    owner: str
    name: str


class ByoTargetImage(BaseModel):
    type: Literal["image"]
    registry: str
    image: str
    tag: str = ""


class ByoFinding(BaseModel):
    target_index: int
    identity_key: str
    tool: str
    severity: str | None = None
    title: str | None = None


class ByoImportRequest(BaseModel):
    scanner: str
    targets: list[ByoTargetRepo | ByoTargetImage]
    findings: list[ByoFinding]


class ByoImportResponse(BaseModel):
    assets: list[str]
    findings_created: int
    scan_runs: list[str]


@router.post("/import", response_model=ByoImportResponse)
@audited(action="scan.byo_imported", resource_type="byo_import")
async def byo_import(
    request: Request,
    payload: ByoImportRequest,
    db: AsyncSession = Depends(_db),
    _: None = Depends(Permission(RUN_SCANS, MANAGE_SOURCES)),
) -> ByoImportResponse:
    user_id = _user_id(request)
    asset_ids: list[str] = []
    display_names: list[str] = []
    try:
        for tgt in payload.targets:
            if tgt.type == "repo":
                ref = repo_ref(tgt.source_type, tgt.owner, tgt.name)
                display = f"{tgt.owner}/{tgt.name}"
            else:
                ref = image_ref(tgt.registry, tgt.image, tgt.tag)
                display = f"{tgt.image}:{tgt.tag or 'latest'}"
            aid = await upsert_asset(
                db, type=tgt.type, source="byo_import",
                external_ref=ref, display_name=display,
                metadata={"scanner": payload.scanner, "uploaded_by": user_id},
            )
            asset_ids.append(aid)
            display_names.append(display)
            await auto_grant_to_uploader(db, asset_id=aid, user_id=user_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    # Per-target severity tallies, counting only newly-created (non-duplicate) findings,
    # so the ScanRun envelope's finding_counts match what this import actually added.
    per_asset_counts: list[dict[str, int]] = [
        {"critical": 0, "high": 0, "medium": 0, "low": 0} for _ in asset_ids
    ]
    created = 0
    for f in payload.findings:
        if f.target_index < 0 or f.target_index >= len(asset_ids):
            raise HTTPException(status_code=400, detail=f"invalid target_index {f.target_index}")
        stmt = pg_insert(Finding).values(
            asset_id=asset_ids[f.target_index],
            tool=f.tool,
            identity_key=f.identity_key,
            severity=f.severity,
            title=f.title,
            state="open",
            engine="byo",
        ).on_conflict_do_nothing(constraint="uq_finding_tool_asset_key")
        result = await db.execute(stmt)
        if result.rowcount:
            created += 1
            bucket = (f.severity or "").strip().lower()
            if bucket in per_asset_counts[f.target_index]:
                per_asset_counts[f.target_index][bucket] += 1

    # Record one terminal ScanRun envelope per target so the import is visible at
    # /scans/{id} and in the scan trail, the same as scanner-triggered runs.
    scan_runs: list[str] = []
    for idx, aid in enumerate(asset_ids):
        scan_runs.append(await record_byo_scan_run(
            db,
            asset_id=aid,
            display_name=display_names[idx],
            scanner=payload.scanner,
            finding_counts=per_asset_counts[idx],
            user_id=user_id,
        ))

    await db.commit()
    return ByoImportResponse(assets=asset_ids, findings_created=created, scan_runs=scan_runs)
