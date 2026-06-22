"""Backward-compatible shim — delegates to grants_store (subject_type='user')."""
from __future__ import annotations

from typing import Any

from src.authz.teams.grants import (
    add_grant,
    list_grants,
    remove_grant,
)


def _to_legacy_dict(g: dict[str, Any]) -> dict[str, Any]:
    return {
        "userId": g["subjectId"],
        "assetId": g["assetId"],
        "source": g["source"],
        "createdAt": g["createdAt"],
    }


def user_has_direct_asset_access(grants: list[dict[str, Any]], user_id: str, asset_id: str) -> bool:
    for grant in grants:
        if grant.get("userId") == user_id and grant.get("assetId") == asset_id:
            return True
    return False


def list_direct_grants() -> list[dict[str, Any]]:
    return [_to_legacy_dict(g) for g in list_grants(subject_type="user")]


def add_direct_grant(user_id: str, asset_id: str, source: str = "manual-direct") -> None:
    add_grant(subject_type="user", subject_id=user_id, asset_id=asset_id, source=source)


def remove_direct_grant(user_id: str, asset_id: str) -> None:
    remove_grant(subject_type="user", subject_id=user_id, asset_id=asset_id)
