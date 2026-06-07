"""REST endpoints for the asset identity layer."""
from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from src.assets.grants import auto_grant_to_uploader
from src.assets.refs import image_ref, repo_ref
from src.assets.service import upsert_asset
from src.db.engine import async_session_factory
from src.db.models import Finding


assets_router = APIRouter(prefix="/api/v1/assets", tags=["assets"])


async def _db():
    async with async_session_factory() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise


class ManualRepoUploadRequest(BaseModel):
    type: Literal["repo"]
    source_type: str
    owner: str
    name: str


class ManualImageUploadRequest(BaseModel):
    type: Literal["image"]
    registry: str
    image: str
    tag: str = ""


class ManualUploadResponse(BaseModel):
    asset_id: str
    external_ref: str


def _user_id(request: Request) -> str:
    user_id = getattr(request.state, "user_sub", None)
    if not user_id:
        raise HTTPException(status_code=401, detail="unauthorized")
    return user_id


@assets_router.post("/manual", response_model=ManualUploadResponse)
async def manual_upload(
    request: Request,
    payload: ManualRepoUploadRequest | ManualImageUploadRequest,
    db: AsyncSession = Depends(_db),
) -> ManualUploadResponse:
    user_id = _user_id(request)
    if payload.type == "repo":
        ref = repo_ref(payload.source_type, payload.owner, payload.name)
        display = f"{payload.owner}/{payload.name}"
    else:
        ref = image_ref(payload.registry, payload.image, payload.tag)
        display = f"{payload.image}:{payload.tag or 'latest'}"
    try:
        asset_id = await upsert_asset(
            db, type=payload.type, source="manual_upload",
            external_ref=ref, display_name=display,
            metadata={"uploaded_by": user_id},
        )
        await auto_grant_to_uploader(db, asset_id=asset_id, user_id=user_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return ManualUploadResponse(asset_id=asset_id, external_ref=ref)


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


scans_router = APIRouter(prefix="/api/v1/scans", tags=["scans"])


@scans_router.post("/import", response_model=ByoImportResponse)
async def byo_import(
    request: Request,
    payload: ByoImportRequest,
    db: AsyncSession = Depends(_db),
) -> ByoImportResponse:
    user_id = _user_id(request)
    asset_ids: list[str] = []
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
            await auto_grant_to_uploader(db, asset_id=aid, user_id=user_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

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
    await db.commit()
    return ByoImportResponse(assets=asset_ids, findings_created=created)
