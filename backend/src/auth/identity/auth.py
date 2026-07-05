"""SCIM bearer-token auth dependency."""
from __future__ import annotations

import hashlib
import hmac

from fastapi import Header, HTTPException, Request
from sqlalchemy import select

from src.db.helpers import run_db
from src.db.models import ScimConfig


def require_scim_auth(
    request: Request,
    authorization: str | None = Header(default=None),
) -> None:
    cfg = run_db(_load_config)
    if cfg is None or not cfg.enabled or cfg.token_hash is None:
        raise HTTPException(status_code=404, detail="Not Found")
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Bearer token required")
    presented = authorization.split(" ", 1)[1].strip()
    presented_hash = hashlib.sha256(presented.encode("utf-8")).hexdigest()
    if not hmac.compare_digest(presented_hash, cfg.token_hash):
        raise HTTPException(status_code=401, detail="Invalid token")


async def _load_config(session) -> ScimConfig | None:
    return (await session.execute(select(ScimConfig).where(ScimConfig.id == 1))).scalar_one_or_none()
