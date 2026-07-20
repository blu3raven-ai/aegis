"""REST API for per-org LLM configuration."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from src.settings.llm.service import (
    LlmConfigUpsert,
    delete_llm_config,
    fetch_llm_config,
    fetch_public_llm_config,
    upsert_llm_config,
)
from src.authz.enforcement.dependencies import Permission
from src.authz.permissions.catalog import MANAGE_SETTINGS
from src.shared.url_guard import UnsafeURLError, assert_sendable_url

_DEFAULT_ORG_ID = "default"


def _resolve_org_id() -> str:
    return _DEFAULT_ORG_ID


router = APIRouter(prefix="/api/v1/settings/llm", tags=["settings"])


class LlmConfigBody(BaseModel):
    api_key: str = Field(..., min_length=1, max_length=512)
    api_base_url: str = Field(..., min_length=4, max_length=512)
    model: str = Field(..., min_length=1, max_length=128)
    scan_token_budget: int = Field(100_000, ge=1_000, le=10_000_000)
    daily_token_budget: int = Field(1_000_000, ge=10_000, le=100_000_000)
    enabled: bool = False


@router.get("")
def get_llm_config(
    request: Request,
    _: None = Depends(Permission(MANAGE_SETTINGS)),
) -> dict:
    cfg = fetch_public_llm_config(_resolve_org_id())
    if cfg is None:
        raise HTTPException(status_code=404, detail="llm_config_not_set")
    return cfg


@router.put("")
def put_llm_config(
    body: LlmConfigBody,
    request: Request,
    _: None = Depends(Permission(MANAGE_SETTINGS)),
) -> dict:
    org_id = _resolve_org_id()
    try:
        upsert_llm_config(LlmConfigUpsert(
            org_id=org_id,
            api_key=body.api_key,
            api_base_url=body.api_base_url,
            model=body.model,
            scan_token_budget=body.scan_token_budget,
            daily_token_budget=body.daily_token_budget,
            enabled=body.enabled,
        ))
    except UnsafeURLError as exc:
        raise HTTPException(status_code=422, detail=f"unsafe_url: {str(exc)[:200]}") from exc
    request.state.audit_metadata = {"enabled": body.enabled, "model": body.model}
    return fetch_public_llm_config(org_id) or {"configured": True}


@router.post("/test")
def test_llm_connection(
    request: Request,
    _: None = Depends(Permission(MANAGE_SETTINGS)),
) -> dict:
    """Round-trip a 1-token chat completion to confirm the stored key works."""
    org_id = _resolve_org_id()
    cfg = fetch_llm_config(org_id)
    if cfg is None:
        raise HTTPException(status_code=404, detail="llm_config_not_set")

    try:
        assert_sendable_url(cfg.api_base_url)
    except UnsafeURLError as exc:
        return {"ok": False, "error": "unsafe_url", "detail": str(exc)[:200]}

    import httpx
    try:
        with httpx.Client(timeout=15.0, follow_redirects=False) as client:
            resp = client.post(
                f"{cfg.api_base_url.rstrip('/')}/chat/completions",
                json={
                    "model": cfg.model,
                    "messages": [{"role": "user", "content": "ping"}],
                    "max_tokens": 1,
                },
                headers={
                    "Authorization": f"Bearer {cfg.api_key}",
                    "Content-Type": "application/json",
                },
            )
    except httpx.RequestError as exc:
        return {"ok": False, "error": "network", "detail": str(exc)[:200]}

    if resp.status_code in (200, 201):
        return {"ok": True}
    if resp.status_code in (401, 403):
        return {"ok": False, "error": "auth_failed", "status": resp.status_code}
    return {
        "ok": False,
        "error": f"http_{resp.status_code}",
        "detail": resp.text[:200],
    }


@router.delete("")
def delete_llm_config_route(
    request: Request,
    _: None = Depends(Permission(MANAGE_SETTINGS)),
) -> dict:
    org_id = _resolve_org_id()
    deleted = delete_llm_config(org_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="llm_config_not_set")
    return {"deleted": True}
