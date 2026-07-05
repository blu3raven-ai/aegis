"""API key middleware — populates request.state for authenticated key holders."""
from __future__ import annotations

from fastapi import Request

from src.auth.credentials.auth import verify_api_key


async def try_api_key_auth(request: Request, token: str) -> object | None:
    """Attempt API key authentication.

    Populates request.state fields consistent with JWT auth so downstream
    route handlers work without modification.
    """
    auth_header = f"Bearer {token}"
    row = await verify_api_key(auth_header)
    if row is None:
        return None

    request.state.user_sub = f"api_key:{row.id}"
    request.state.user_role = "viewer"
    request.state.user_role_id = None
    request.state.api_key_id = row.id
    request.state.api_key_scopes = list(row.scopes or [])
    request.state.api_key_allowed_source_ids = (
        list(row.allowed_source_ids) if row.allowed_source_ids else None
    )

    # Record last_used_at — best-effort
    try:
        from src.auth.credentials.service import record_usage
        await record_usage(row.id)
    except Exception:
        pass

    return row
