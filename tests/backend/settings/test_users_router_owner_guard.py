"""Tests for owner-role authorization guards on workspace user management.

Covers three operations on the workspace service layer (called by the REST
routers under /api/v1/workspace/users/*):
  * create_user           — promote new user to owner
  * update_user_role      — change role to/from owner
  * delete_user_mutation  — delete an owner user

For each, three scenarios are exercised:
  - actor is owner → guard passes
  - actor has a custom role with manage_owner_role explicitly → guard passes
  - actor is admin without manage_owner_role → raises PERMISSION_DENIED

The service functions still raise ``GraphQLError`` with coded ``extensions``
so both the GraphQL surface (where it still applies) and the REST routers
(via ``raise_for_gql``) produce consistent error envelopes.
"""
from __future__ import annotations

import asyncio
import concurrent.futures
import contextlib
import os
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from graphql import GraphQLError

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost:5432/test")
os.environ.setdefault("APP_SECRET", "0" * 64)

from src.auth.workspace.service import (  # noqa: E402
    UserCreateInput,
    UserRoleInput,
    create_user,
    delete_user_mutation,
    update_user_role,
)
from src.authz.permissions.catalog import MANAGE_OWNER_ROLE, MANAGE_USERS  # noqa: E402


_ACTOR_ID = "usr_actor"
_TARGET_ID = "usr_target"

_ROLE_OWNER = {
    "id": "role_owner",
    "name": "Owner",
    "slug": "owner",
    "permissions": ["manage_users", "manage_owner_role", "manage_roles"],
}
_ROLE_ADMIN = {
    "id": "role_admin",
    "name": "Admin",
    "slug": "admin",
    "permissions": ["manage_users", "manage_roles"],
}
_ROLE_CUSTOM_WITH_GRANT = {
    "id": "role_custom_grant",
    "name": "Owner Manager",
    "slug": "custom",
    "permissions": ["manage_users", "manage_owner_role"],
}


def _workspace_ctx(actor_role: str, actor_role_id: str | None) -> dict:
    return {
        "user_id": _ACTOR_ID,
        "role": actor_role,
        "role_id": actor_role_id,
        "tier": "community",
        "request": SimpleNamespace(),
    }


def _role_resolvers(*role_records):
    """Build get_role / get_role_by_slug callables for the given fixture set.

    Patches both src.authz.roles.service (for has_role_permission internals)
    and src.auth.workspace.service (for the resolver's direct calls).
    """
    by_id = {r["id"]: r for r in role_records}
    by_slug = {r["slug"]: r for r in role_records if "slug" in r}

    def get_role(role_id: str) -> dict:
        if role_id in by_id:
            return by_id[role_id]
        raise ValueError(f"Role not found: {role_id}")

    def get_role_by_slug(slug: str) -> dict:
        if slug in by_slug:
            return by_slug[slug]
        raise ValueError(f"Role not found: {slug}")

    return [
        patch("src.authz.roles.service.get_role", side_effect=get_role),
        patch("src.authz.roles.service.get_role_by_slug", side_effect=get_role_by_slug),
        patch("src.auth.workspace.service.get_role", side_effect=get_role),
        patch("src.auth.workspace.service.get_role_by_slug", side_effect=get_role_by_slug),
    ]


def _common_patches():
    return [
        patch("src.auth.workspace.service.has_permission", return_value=True),
        patch("src.auth.workspace.service.record_event"),
        patch("src.auth.workspace.service._lookup_username", return_value="actor"),
        patch("src.license.limits.check_limit", return_value=None),
        patch("src.license.limits.check_feature", return_value=None),
    ]


def _stack_with(patches):
    stack = contextlib.ExitStack()
    for p in patches:
        stack.enter_context(p)
    return stack


def _run_coro_in_thread(coro_fn, session):
    """Run a coroutine against the given session in a worker thread.

    Avoids the nested-event-loop issue that arises when sync run_db is called
    from an already-running pytest-asyncio test loop.
    """
    def _runner():
        return asyncio.run(coro_fn(session))

    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
        return ex.submit(_runner).result()


def _fake_run_db_for_coroutine(session):
    """Return a run_db side_effect that executes the first coroutine against
    the provided fake session; subsequent calls return None."""
    calls = [0]

    def _run_db(coro_fn):
        calls[0] += 1
        if calls[0] == 1:
            return _run_coro_in_thread(coro_fn, session)
        return None

    return _run_db


# ---------------------------------------------------------------------------
# create_user — guard fires outside the DB coroutine
# ---------------------------------------------------------------------------

_VALID_PASSWORD = "supersecret-1234"

_NEW_USER_DICT = {
    "id": "usr_new",
    "username": "newuser",
    "email": "newuser@example.com",
    "role": "owner",
    "roleId": "role_owner",
    "status": "active",
    "createdAt": "2026-01-01T00:00:00.000Z",
    "updatedAt": "2026-01-01T00:00:00.000Z",
    "passwordResetRequired": False,
    "totpEnabled": False,
}


def _create_input(role: str = "owner") -> UserCreateInput:
    return UserCreateInput(
        username="newuser",
        email="newuser@example.com",
        password=_VALID_PASSWORD,
        role=role,
    )


def test_create_user_promotes_to_owner_when_actor_is_owner():
    patches = [
        *_role_resolvers(_ROLE_OWNER),
        *_common_patches(),
        patch("src.auth.workspace.service.run_db", side_effect=[0, _NEW_USER_DICT]),
    ]
    with _stack_with(patches):
        result = create_user(
            input=_create_input("owner"),
            info_context=_workspace_ctx("owner", "role_owner"),
        )

    assert result.id == "usr_new"


def test_create_user_promotes_to_owner_when_actor_has_explicit_grant():
    patches = [
        *_role_resolvers(_ROLE_OWNER, _ROLE_CUSTOM_WITH_GRANT),
        *_common_patches(),
        patch("src.auth.workspace.service.run_db", side_effect=[0, _NEW_USER_DICT]),
    ]
    with _stack_with(patches):
        result = create_user(
            input=_create_input("owner"),
            info_context=_workspace_ctx("custom", "role_custom_grant"),
        )

    assert result.id == "usr_new"


def test_create_user_rejects_promotion_to_owner_without_grant():
    patches = [
        *_role_resolvers(_ROLE_OWNER, _ROLE_ADMIN),
        *_common_patches(),
        patch("src.auth.workspace.service.run_db", return_value=0),
    ]
    with _stack_with(patches):
        with pytest.raises(GraphQLError) as exc_info:
            create_user(
                input=_create_input("owner"),
                info_context=_workspace_ctx("admin", "role_admin"),
            )

    err = exc_info.value
    assert err.extensions["code"] == "PERMISSION_DENIED"
    assert "manage_owner_role" in err.message


# ---------------------------------------------------------------------------
# update_user_role — guard fires inside the DB coroutine for some scenarios
# ---------------------------------------------------------------------------

class _FakeUpdateSession:
    def __init__(self, target_role_id: str = "role_admin"):
        self._user = SimpleNamespace(
            id=_TARGET_ID,
            username="target",
            email="target@example.com",
            role_id=target_role_id,
            status="active",
            session_version=1,
            created_at=None,
            updated_at=None,
            password_reset_required=False,
            totp_enabled=False,
        )

    async def get(self, _model, _key):
        return self._user

    async def execute(self, *_args, **_kwargs):
        class _R:
            def scalar(self):
                return 5

            def scalars(self):
                class _S:
                    def all(self):
                        return ["o1", "o2", "o3", "o4", "o5"]

                return _S()

        return _R()

    async def flush(self):
        pass


def test_update_user_role_to_owner_passes_when_actor_is_owner():
    patches = [
        *_role_resolvers(_ROLE_OWNER),
        *_common_patches(),
        patch(
            "src.auth.workspace.service.run_db",
            side_effect=_fake_run_db_for_coroutine(_FakeUpdateSession("role_admin")),
        ),
    ]
    with _stack_with(patches):
        result = update_user_role(
            user_id=_TARGET_ID,
            input=UserRoleInput(role="owner"),
            info_context=_workspace_ctx("owner", "role_owner"),
        )

    assert result.id == _TARGET_ID


def test_update_user_role_to_owner_passes_with_explicit_grant():
    custom_role = {**_ROLE_CUSTOM_WITH_GRANT, "permissions": list(_ROLE_OWNER["permissions"])}
    patches = [
        *_role_resolvers(_ROLE_OWNER, custom_role),
        *_common_patches(),
        patch(
            "src.auth.workspace.service.run_db",
            side_effect=_fake_run_db_for_coroutine(_FakeUpdateSession("role_admin")),
        ),
    ]
    with _stack_with(patches):
        result = update_user_role(
            user_id=_TARGET_ID,
            input=UserRoleInput(role="owner"),
            info_context=_workspace_ctx("custom", "role_custom_grant"),
        )

    assert result.id == _TARGET_ID


def test_update_user_role_to_owner_rejected_without_grant():
    """Escalation guard (outside the coroutine) blocks admin promoting to owner."""
    patches = [
        *_role_resolvers(_ROLE_OWNER, _ROLE_ADMIN),
        *_common_patches(),
        patch("src.auth.workspace.service.run_db", return_value=None),
    ]
    with _stack_with(patches):
        with pytest.raises(GraphQLError) as exc_info:
            update_user_role(
                user_id=_TARGET_ID,
                input=UserRoleInput(role="owner"),
                info_context=_workspace_ctx("admin", "role_admin"),
            )

    err = exc_info.value
    assert err.extensions["code"] == "PERMISSION_DENIED"


def test_update_user_role_demoting_owner_rejected_without_grant():
    """Admin cannot demote an existing owner — guard fires inside the DB coroutine."""
    patches = [
        *_role_resolvers(_ROLE_OWNER, _ROLE_ADMIN),
        *_common_patches(),
        patch(
            "src.auth.workspace.service.run_db",
            side_effect=_fake_run_db_for_coroutine(_FakeUpdateSession("role_owner")),
        ),
    ]
    with _stack_with(patches):
        with pytest.raises(GraphQLError) as exc_info:
            update_user_role(
                user_id=_TARGET_ID,
                input=UserRoleInput(role="admin"),
                info_context=_workspace_ctx("admin", "role_admin"),
            )

    err = exc_info.value
    assert err.extensions["code"] == "PERMISSION_DENIED"
    assert "manage_owner_role" in err.message


# ---------------------------------------------------------------------------
# delete_user_mutation — guard fires inside the DB coroutine
# ---------------------------------------------------------------------------

class _FakeDeleteSession:
    def __init__(self, target_role_id: str = "role_owner"):
        self._user = SimpleNamespace(
            id=_TARGET_ID,
            username="target",
            role_id=target_role_id,
            status="active",
        )

    async def get(self, _model, _key):
        return self._user

    async def execute(self, *_args, **_kwargs):
        class _R:
            def scalar(self):
                return 5

            def scalars(self):
                class _S:
                    def all(self):
                        return ["o1", "o2", "o3", "o4", "o5"]

                return _S()

        return _R()

    async def delete(self, _obj):
        pass


def test_delete_owner_user_passes_when_actor_is_owner():
    patches = [
        *_role_resolvers(_ROLE_OWNER),
        *_common_patches(),
        patch(
            "src.auth.workspace.service.run_db",
            side_effect=_fake_run_db_for_coroutine(_FakeDeleteSession()),
        ),
    ]
    with _stack_with(patches):
        result = delete_user_mutation(
            user_id=_TARGET_ID,
            info_context=_workspace_ctx("owner", "role_owner"),
        )

    assert result.ok is True


def test_delete_owner_user_passes_with_explicit_grant():
    patches = [
        *_role_resolvers(_ROLE_CUSTOM_WITH_GRANT),
        *_common_patches(),
        patch(
            "src.auth.workspace.service.run_db",
            side_effect=_fake_run_db_for_coroutine(_FakeDeleteSession()),
        ),
    ]
    with _stack_with(patches):
        result = delete_user_mutation(
            user_id=_TARGET_ID,
            info_context=_workspace_ctx("custom", "role_custom_grant"),
        )

    assert result.ok is True


def test_delete_owner_user_rejected_without_grant():
    patches = [
        *_role_resolvers(_ROLE_ADMIN),
        *_common_patches(),
        patch(
            "src.auth.workspace.service.run_db",
            side_effect=_fake_run_db_for_coroutine(_FakeDeleteSession()),
        ),
    ]
    with _stack_with(patches):
        with pytest.raises(GraphQLError) as exc_info:
            delete_user_mutation(
                user_id=_TARGET_ID,
                info_context=_workspace_ctx("admin", "role_admin"),
            )

    err = exc_info.value
    assert err.extensions["code"] == "PERMISSION_DENIED"
    assert "manage_owner_role" in err.message
