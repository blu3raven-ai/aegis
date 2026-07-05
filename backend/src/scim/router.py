"""SCIM 2.0 routes — Users CRUD; Groups returns 501."""
from __future__ import annotations

import re
import secrets
from typing import Any

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import JSONResponse, Response
from sqlalchemy import func, select

from src.db.helpers import run_db
from src.db.models import ScimConfig, User
from src.scim.auth import require_scim_auth
from src.scim.schemas import ScimUser

scim_router = APIRouter(prefix="/scim/v2", tags=["scim"], dependencies=[Depends(require_scim_auth)])


def _origin(request: Request) -> str:
    return f"{request.url.scheme}://{request.headers.get('host') or request.url.netloc}"


def _to_scim(row: User, request: Request) -> dict[str, Any]:
    return {
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "id": row.id,
        "userName": row.username,
        "active": row.status != "deprovisioned",
        "emails": [{"value": row.email, "primary": True, "type": "work"}] if row.email else [],
        "meta": {
            "resourceType": "User",
            "location": f"{_origin(request)}/scim/v2/Users/{row.id}",
        },
    }


async def _load_default_role(session) -> str | None:
    cfg = (await session.execute(select(ScimConfig).where(ScimConfig.id == 1))).scalar_one_or_none()
    return cfg.default_role_id if cfg else None


def _scim_error(status: int, scim_type: str | None, detail: str) -> JSONResponse:
    body = {
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
        "status": str(status),
        "detail": detail,
    }
    if scim_type:
        body["scimType"] = scim_type
    return JSONResponse(body, status_code=status)


@scim_router.get("/ServiceProviderConfig")
def service_provider_config() -> dict:
    return {
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
        "patch": {"supported": True},
        "bulk": {"supported": False, "maxOperations": 0, "maxPayloadSize": 0},
        "filter": {"supported": True, "maxResults": 200},
        "changePassword": {"supported": False},
        "sort": {"supported": False},
        "etag": {"supported": False},
        "authenticationSchemes": [
            {"type": "oauthbearertoken", "name": "OAuth Bearer Token", "description": "RFC 6750 bearer"},
        ],
    }


@scim_router.get("/ResourceTypes")
def resource_types() -> dict:
    return {
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
        "totalResults": 1,
        "Resources": [
            {
                "id": "User",
                "name": "User",
                "endpoint": "/Users",
                "schema": "urn:ietf:params:scim:schemas:core:2.0:User",
            },
        ],
    }


@scim_router.get("/Schemas")
def schemas() -> dict:
    return {
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
        "totalResults": 1,
        "Resources": [
            {
                "id": "urn:ietf:params:scim:schemas:core:2.0:User",
                "name": "User",
                "description": "SCIM core User",
                "attributes": [
                    {
                        "name": "userName",
                        "type": "string",
                        "multiValued": False,
                        "required": True,
                        "caseExact": False,
                        "mutability": "readWrite",
                        "returned": "default",
                        "uniqueness": "server",
                    },
                    {
                        "name": "active",
                        "type": "boolean",
                        "multiValued": False,
                        "required": False,
                        "mutability": "readWrite",
                        "returned": "default",
                    },
                    {
                        "name": "emails",
                        "type": "complex",
                        "multiValued": True,
                        "required": False,
                        "mutability": "readWrite",
                        "returned": "default",
                        "subAttributes": [
                            {
                                "name": "value",
                                "type": "string",
                                "required": True,
                                "mutability": "readWrite",
                                "returned": "default",
                            },
                            {
                                "name": "primary",
                                "type": "boolean",
                                "required": False,
                                "mutability": "readWrite",
                                "returned": "default",
                            },
                            {
                                "name": "type",
                                "type": "string",
                                "required": False,
                                "mutability": "readWrite",
                                "returned": "default",
                            },
                        ],
                    },
                ],
            },
        ],
    }


_USERNAME_EQ_RE = re.compile(r'userName\s+eq\s+"([^"]+)"')


@scim_router.get("/Users")
def list_users(
    request: Request,
    filter: str | None = Query(default=None),
    startIndex: int = Query(default=1, ge=1),
    count: int = Query(default=100, ge=0, le=200),
) -> JSONResponse:
    async def _q(session):
        stmt = select(User).where(User.status != "deprovisioned")
        if filter:
            m = _USERNAME_EQ_RE.search(filter)
            if not m:
                return None
            stmt = stmt.where(User.username == m.group(1))
        total_stmt = select(func.count()).select_from(stmt.subquery())
        total = (await session.execute(total_stmt)).scalar_one()
        rows = (await session.execute(stmt.offset(startIndex - 1).limit(count))).scalars().all()
        return {
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
            "totalResults": total,
            "startIndex": startIndex,
            "itemsPerPage": len(rows),
            "Resources": [_to_scim(r, request) for r in rows],
        }

    result = run_db(_q)
    if result is None:
        return _scim_error(400, "invalidFilter", "Unsupported filter; only `userName eq` is supported.")
    return JSONResponse(result, status_code=200)


@scim_router.post("/Users")
def create_user(request: Request, body: ScimUser) -> JSONResponse:
    email = body.emails[0].value if body.emails else body.userName

    async def _q(session):
        existing = (
            await session.execute(select(User).where(User.username == body.userName))
        ).scalar_one_or_none()
        if existing is not None:
            return ("conflict", existing)
        default_role_id = await _load_default_role(session)
        user = User(
            id=f"scim-{secrets.token_urlsafe(12)}",
            username=body.userName,
            email=email,
            password_hash="",
            role_id=default_role_id,
            status="active" if body.active else "deprovisioned",
        )
        session.add(user)
        await session.flush()
        return ("created", user)

    kind, user = run_db(_q)
    if kind == "conflict":
        return _scim_error(409, "uniqueness", "userName already exists.")
    return JSONResponse(_to_scim(user, request), status_code=201)


@scim_router.get("/Users/{user_id}")
def get_user(request: Request, user_id: str) -> JSONResponse:
    async def _q(session):
        return (await session.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
    row = run_db(_q)
    if row is None:
        return _scim_error(404, None, "User not found.")
    return JSONResponse(_to_scim(row, request), status_code=200)


@scim_router.put("/Users/{user_id}")
def replace_user(request: Request, user_id: str, body: ScimUser) -> JSONResponse:
    async def _q(session):
        row = (await session.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
        if row is None:
            return None
        row.username = body.userName
        if body.emails:
            row.email = body.emails[0].value
        row.status = "active" if body.active else "deprovisioned"
        return row
    row = run_db(_q)
    if row is None:
        return _scim_error(404, None, "User not found.")
    return JSONResponse(_to_scim(row, request), status_code=200)


@scim_router.patch("/Users/{user_id}")
def patch_user(request: Request, user_id: str, body: dict[str, Any]) -> JSONResponse:
    ops = body.get("Operations") or []

    async def _q(session):
        row = (await session.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
        if row is None:
            return None
        for op in ops:
            path = (op.get("path") or "").strip()
            value = op.get("value")
            if path == "active" or path == "":
                if isinstance(value, dict) and "active" in value:
                    row.status = "active" if value["active"] else "deprovisioned"
                elif isinstance(value, bool):
                    row.status = "active" if value else "deprovisioned"
            elif path == "userName":
                if isinstance(value, str):
                    row.username = value
            elif path == "emails":
                if isinstance(value, list) and value and isinstance(value[0], dict):
                    row.email = str(value[0].get("value") or row.email)
        return row

    row = run_db(_q)
    if row is None:
        return _scim_error(404, None, "User not found.")
    return JSONResponse(_to_scim(row, request), status_code=200)


@scim_router.delete("/Users/{user_id}")
def delete_user(user_id: str) -> Response:
    async def _q(session):
        row = (await session.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
        if row is None:
            return False
        row.status = "deprovisioned"
        return True
    ok = run_db(_q)
    if not ok:
        return Response(status_code=404)
    return Response(status_code=204)


@scim_router.api_route("/Groups", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
@scim_router.api_route("/Groups/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
def groups_unsupported() -> JSONResponse:
    return _scim_error(501, None, "Groups are not yet implemented.")
