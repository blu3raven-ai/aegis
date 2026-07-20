"""Privilege-escalation guard on the role-write paths.

A `manage_roles` holder must never mint, edit, or reassign users into a role
whose permission set exceeds their own — otherwise an admin could grant itself
`manage_owner_role` (or any permission) by defining or reassigning a role. The
user-assignment paths already enforce this; these tests pin the same guard on
`create_role_mutation`, `update_role_mutation`, and the delete-with-replacement
reassignment.
"""
from __future__ import annotations

import os
from unittest.mock import patch

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost:5432/test")

import pytest
from graphql import GraphQLError

import src.auth.workspace.service as svc
from src.auth.workspace.service import (
    RoleInput,
    _reject_permission_escalation,
    create_role_mutation,
    delete_role_mutation,
    update_role_mutation,
)

# Actor is an admin: holds manage_roles, NOT manage_owner_role.
_ACTOR_PERMS = {"manage_roles", "view_findings", "view_roles"}
_CTX = {"request": object(), "role": "admin", "role_id": None}


def _resolve(record):
    """Fake resolve_role_permissions: record is the perm set itself."""
    return set(record)


def _guarded(**extra):
    """Patch the guard's dependencies so the actor holds _ACTOR_PERMS."""
    return patch.multiple(
        svc,
        has_permission=lambda *a, **k: True,  # MANAGE_ROLES gate passes
        get_role_by_slug=lambda slug: _ACTOR_PERMS,
        resolve_role_permissions=_resolve,
        **extra,
    )


# ── the guard itself ─────────────────────────────────────────────────────────

def test_guard_allows_subset():
    with _guarded():
        _reject_permission_escalation(_CTX, {"view_findings"})  # no raise


def test_guard_blocks_unheld_permission():
    with _guarded(), pytest.raises(GraphQLError) as ei:
        _reject_permission_escalation(_CTX, {"manage_owner_role"})
    assert ei.value.extensions["code"] == "PERMISSION_DENIED"


# ── wired into every role-write path ─────────────────────────────────────────

def test_create_role_blocks_escalation():
    with _guarded(_check_feature=lambda *a, **k: None,
                  _create_role=lambda *a, **k: pytest.fail("write ran despite escalation")):
        with pytest.raises(GraphQLError):
            create_role_mutation(
                input=RoleInput(name="X", description="", permissions=["manage_owner_role"]),
                info_context=_CTX,
            )


def test_update_role_blocks_escalation():
    with _guarded(_update_role=lambda *a, **k: pytest.fail("write ran despite escalation")):
        with pytest.raises(GraphQLError):
            update_role_mutation(
                role_id="role_admin",
                input=RoleInput(name="Admin", description="", permissions=["manage_owner_role"]),
                info_context=_CTX,
            )


def test_delete_role_blocks_reassign_to_more_privileged():
    # Replacement role carries manage_owner_role the actor lacks.
    owner_perms = _ACTOR_PERMS | {"manage_owner_role"}
    with _guarded(get_role=lambda rid: owner_perms,
                  _delete_role=lambda *a, **k: pytest.fail("reassign ran despite escalation")):
        with pytest.raises(GraphQLError):
            delete_role_mutation(
                role_id="role_admin",
                replacement_role_id="role_owner",
                info_context=_CTX,
            )


def test_update_role_allows_non_escalating_write():
    calls = []
    with _guarded(
        _update_role=lambda *a, **k: calls.append((a, k)) or {"id": "role-x"},
        _role_from_dict=lambda d: d,
    ):
        update_role_mutation(
            role_id="role-x",
            input=RoleInput(name="Auditor", description="", permissions=["view_findings"]),
            info_context=_CTX,
        )
    assert calls, "non-escalating update should reach the write"
