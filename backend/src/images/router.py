"""REST endpoint for the /api/v1/images aggregator."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query, Request

from src.db.engine import async_session_factory
from src.images.models import FindingCounts, ImageListResponse, ImageRow
from src.images.service import list_images
from src.settings.router import require_permission
from src.shared.scope import get_user_asset_ids

router = APIRouter(prefix="/api/v1/images", tags=["images"])


@router.get("", response_model=ImageListResponse, summary="List scanned container images")
async def list_images_endpoint(
    request: Request,
    cursor: str | None = Query(None, description="Opaque cursor from a previous response"),
    limit: int = Query(50, ge=1, le=200, description="Page size"),
) -> ImageListResponse:
    require_permission(request, "view_findings")
    ctx = {"user_id": request.state.user_sub, "role": getattr(request.state, "user_role", "viewer")}
    async with async_session_factory() as db:
        asset_ids = await get_user_asset_ids(db, ctx)

    try:
        result = await list_images(asset_ids=asset_ids, cursor=cursor, limit=limit)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    return ImageListResponse(
        images=[
            ImageRow(
                image_digest=img.image_digest,
                image_name=img.image_name,
                image_tag=img.image_tag,
                first_seen_at=img.first_seen_at.isoformat(),
                last_scanned_at=img.last_scanned_at.isoformat() if img.last_scanned_at else None,
                finding_counts=FindingCounts(
                    critical=img.critical,
                    high=img.high,
                    medium=img.medium,
                    low=img.low,
                ),
                repos=img.repos,
                layer_count=img.layer_count,
                size_bytes=img.size_bytes,
                base_os=img.base_os,
            )
            for img in result.images
        ],
        next_cursor=result.next_cursor,
        total_count=result.total_count,
    )
