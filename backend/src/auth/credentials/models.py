"""API key record — Pydantic view layer over the ORM model in db.models."""
from __future__ import annotations

from datetime import datetime

# ORM model lives in the central models file so Base.metadata.create_all covers it
from src.db.models import ApiKey  # noqa: F401  (re-export for convenience)


class ApiKeyRecord:
    """Safe view of an ApiKey row — never includes token_hash."""

    def __init__(
        self,
        id: int,
        name: str,
        prefix: str,
        last_four: str,
        scopes: list[str],
        created_by: str | None,
        created_at: datetime,
        last_used_at: datetime | None,
        expires_at: datetime | None,
        revoked_at: datetime | None,
    ) -> None:
        self.id = id
        self.name = name
        self.prefix = prefix
        self.last_four = last_four
        self.scopes = scopes
        self.created_by = created_by
        self.created_at = created_at
        self.last_used_at = last_used_at
        self.expires_at = expires_at
        self.revoked_at = revoked_at

    @classmethod
    def from_orm(cls, row: "ApiKey") -> "ApiKeyRecord":
        return cls(
            id=row.id,
            name=row.name,
            prefix=row.prefix,
            last_four=row.last_four,
            scopes=list(row.scopes or []),
            created_by=row.created_by,
            created_at=row.created_at,
            last_used_at=row.last_used_at,
            expires_at=row.expires_at,
            revoked_at=row.revoked_at,
        )

    def to_dict(self) -> dict:
        def _iso(dt: datetime | None) -> str | None:
            return dt.isoformat() if dt else None

        return {
            "id": self.id,
            "name": self.name,
            "prefix": self.prefix,
            "last_four": self.last_four,
            "scopes": self.scopes,
            "created_by": self.created_by,
            "created_at": _iso(self.created_at),
            "last_used_at": _iso(self.last_used_at),
            "expires_at": _iso(self.expires_at),
            "revoked_at": _iso(self.revoked_at),
        }
