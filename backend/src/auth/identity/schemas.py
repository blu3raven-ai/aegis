"""SCIM 2.0 User schema shapes per RFC 7643."""
from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class ScimEmail(BaseModel):
    value: str
    primary: bool = True
    type: str | None = "work"


class ScimName(BaseModel):
    givenName: str | None = None
    familyName: str | None = None
    formatted: str | None = None


class ScimUser(BaseModel):
    schemas: list[str] = Field(default_factory=lambda: ["urn:ietf:params:scim:schemas:core:2.0:User"])
    id: str | None = None
    userName: str
    active: bool = True
    name: ScimName | None = None
    emails: list[ScimEmail] = Field(default_factory=list)
    meta: dict[str, Any] | None = None


class ScimListResponse(BaseModel):
    schemas: list[str] = Field(default_factory=lambda: ["urn:ietf:params:scim:api:messages:2.0:ListResponse"])
    totalResults: int
    startIndex: int = 1
    itemsPerPage: int
    Resources: list[dict[str, Any]] = Field(default_factory=list)


class ScimError(BaseModel):
    schemas: list[str] = Field(default_factory=lambda: ["urn:ietf:params:scim:api:messages:2.0:Error"])
    status: str
    detail: str
    scimType: str | None = None
