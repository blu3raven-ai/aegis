"""SBOM download API — enterprise-gated CycloneDX export."""
from __future__ import annotations

import json

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse, Response

from src.license.limits import check_feature
from src.settings.router import require_permission
from src.shared.router_helpers import require_orgs
from src.shared.sbom_storage import download_from_minio, safe_s3_segment

router = APIRouter(prefix="/api/v1/sbom", tags=["sbom"])


@router.get("/download")
def download_sbom(
    request: Request,
    org: str,
    repo: str,
    orgs: list[str] = Depends(require_orgs),
) -> Response:
    """Download a CycloneDX SBOM JSON for a specific org/repo."""
    check_feature(request, "sbom_export")
    require_permission(request, "view_findings")

    if org.lower() not in [o.lower() for o in orgs]:
        return JSONResponse({"error": "Organization not accessible"}, status_code=403)

    safe_org = safe_s3_segment(org)
    safe_repo = safe_s3_segment(repo)
    key = f"{safe_org}/{safe_repo}/sbom.cdx.json"

    data = download_from_minio(key)
    if data is None:
        return JSONResponse({"error": "SBOM not found for this repository"}, status_code=404)

    filename = f"{safe_org}_{safe_repo}_sbom.cdx.json"
    return Response(
        content=json.dumps(data, indent=2),
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
