"""Unit tests for SCIM 2.0 router.

These tests stub out run_db so the router can be exercised without a
real database. Bearer-auth checks and group-deferral invariants are
verified end-to-end through the FastAPI TestClient.
"""
from __future__ import annotations

import hashlib
import os
from unittest.mock import patch

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost:5432/test")
os.environ.setdefault("RUNNER_ENCRYPTION_KEY", "0" * 64)

from fastapi.testclient import TestClient  # noqa: E402

from src.db.models import ScimConfig, User  # noqa: E402
from src.auth.identity.router import scim_router  # noqa: E402


_RAW_TOKEN = "scim-router-test-token"
_TOKEN_HASH = hashlib.sha256(_RAW_TOKEN.encode("utf-8")).hexdigest()


def _mount() -> TestClient:
    from fastapi import FastAPI
    app = FastAPI()
    app.include_router(scim_router)
    return TestClient(app)


def _enabled_cfg(default_role_id: str | None = None) -> ScimConfig:
    cfg = ScimConfig()
    cfg.id = 1
    cfg.enabled = True
    cfg.token_hash = _TOKEN_HASH
    cfg.default_role_id = default_role_id
    return cfg


def _disabled_cfg() -> ScimConfig:
    cfg = ScimConfig()
    cfg.id = 1
    cfg.enabled = False
    cfg.token_hash = None
    return cfg


async def _seed_enabled_scim_config(session) -> None:
    """Atomically enable the singleton ScimConfig (id=1) for db-backed tests.

    The previous read-then-add pattern was a check-then-act race on the shared
    singleton row: two db-backed tests running concurrently (e.g. under
    pytest-xdist against one database) could both observe no row and then both
    insert id=1, colliding on the primary key. An upsert converges atomically
    regardless of interleaving.
    """
    from sqlalchemy.dialects.postgresql import insert as _pg_insert

    stmt = (
        _pg_insert(ScimConfig)
        .values(id=1, enabled=True, token_hash=_TOKEN_HASH, default_role_id=None)
        .on_conflict_do_update(
            index_elements=[ScimConfig.id],
            set_={"enabled": True, "token_hash": _TOKEN_HASH, "default_role_id": None},
        )
    )
    await session.execute(stmt)


def _auth_headers() -> dict:
    return {"Authorization": f"Bearer {_RAW_TOKEN}"}


def _user(
    id_: str,
    username: str,
    email: str = "",
    status: str = "active",
    scim_managed: bool = True,
) -> User:
    u = User()
    u.id = id_
    u.username = username
    u.email = email or f"{username}@example.com"
    u.password_hash = ""
    u.status = status
    u.role_id = None
    u.scim_managed = scim_managed
    return u




def test_scim_disabled_returns_404_for_users_endpoint():
    with patch("src.auth.identity.auth.run_db", return_value=_disabled_cfg()):
        client = _mount()
        resp = client.get("/scim/v2/Users", headers=_auth_headers())
    assert resp.status_code == 404


def test_scim_wrong_scheme_returns_401():
    with patch("src.auth.identity.auth.run_db", return_value=_enabled_cfg()):
        client = _mount()
        resp = client.get("/scim/v2/Users", headers={"Authorization": "Basic xxx"})
    assert resp.status_code == 401


def test_scim_invalid_bearer_token_returns_401():
    with patch("src.auth.identity.auth.run_db", return_value=_enabled_cfg()):
        client = _mount()
        resp = client.get(
            "/scim/v2/Users",
            headers={"Authorization": "Bearer not-the-right-token"},
        )
    assert resp.status_code == 401




def test_service_provider_config_declares_patch_and_no_bulk():
    with patch("src.auth.identity.auth.run_db", return_value=_enabled_cfg()):
        client = _mount()
        resp = client.get("/scim/v2/ServiceProviderConfig", headers=_auth_headers())
    assert resp.status_code == 200
    body = resp.json()
    assert body["patch"]["supported"] is True
    assert body["bulk"]["supported"] is False
    assert any(s["type"] == "oauthbearertoken" for s in body["authenticationSchemes"])


def test_schemas_endpoint_includes_user_resource():
    with patch("src.auth.identity.auth.run_db", return_value=_enabled_cfg()):
        client = _mount()
        resp = client.get("/scim/v2/Schemas", headers=_auth_headers())
    assert resp.status_code == 200
    body = resp.json()
    assert any(r["id"].endswith(":User") for r in body["Resources"])




def test_post_user_returns_201_with_required_scim_fields():
    cfg = _enabled_cfg(default_role_id="role_admin")
    created = _user("scim-newid", "alice@example.com", "alice@example.com")

    auth_calls = {"n": 0}

    def fake_run_db(coro_fn):
        # First call is auth lookup, second is the create
        auth_calls["n"] += 1
        if auth_calls["n"] == 1:
            return cfg
        return ("created", created)

    with patch("src.auth.identity.auth.run_db", side_effect=fake_run_db), \
         patch("src.auth.identity.router.run_db", side_effect=fake_run_db):
        client = _mount()
        resp = client.post(
            "/scim/v2/Users",
            json={
                "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
                "userName": "alice@example.com",
                "emails": [{"value": "alice@example.com", "primary": True}],
                "active": True,
            },
            headers=_auth_headers(),
        )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["id"] == "scim-newid"
    assert body["schemas"] == ["urn:ietf:params:scim:schemas:core:2.0:User"]
    assert body["meta"]["resourceType"] == "User"
    assert body["meta"]["location"].endswith(f"/scim/v2/Users/{created.id}")
    assert body["active"] is True
    assert body["emails"][0]["value"] == "alice@example.com"


def test_post_user_missing_username_returns_400():
    # Auth pass-through; pydantic should reject the body before run_db fires.
    with patch("src.auth.identity.auth.run_db", return_value=_enabled_cfg()):
        client = _mount()
        resp = client.post(
            "/scim/v2/Users",
            json={"emails": [{"value": "x@example.com"}]},
            headers=_auth_headers(),
        )
    # FastAPI/pydantic returns 422 for missing required fields.
    assert resp.status_code == 422


def test_post_user_duplicate_username_returns_409_uniqueness():
    cfg = _enabled_cfg()
    existing = _user("u-existing", "dup@example.com")

    auth_calls = {"n": 0}

    def fake_run_db(coro_fn):
        auth_calls["n"] += 1
        if auth_calls["n"] == 1:
            return cfg
        return ("conflict", existing)

    with patch("src.auth.identity.auth.run_db", side_effect=fake_run_db), \
         patch("src.auth.identity.router.run_db", side_effect=fake_run_db):
        client = _mount()
        resp = client.post(
            "/scim/v2/Users",
            json={"userName": "dup@example.com"},
            headers=_auth_headers(),
        )
    assert resp.status_code == 409
    body = resp.json()
    assert body["status"] == "409"
    assert body["scimType"] == "uniqueness"


def test_post_user_with_active_false_marks_as_deprovisioned():
    cfg = _enabled_cfg()
    created = _user("scim-inactive", "bob@example.com", status="deprovisioned")

    auth_calls = {"n": 0}

    def fake_run_db(coro_fn):
        auth_calls["n"] += 1
        if auth_calls["n"] == 1:
            return cfg
        return ("created", created)

    with patch("src.auth.identity.auth.run_db", side_effect=fake_run_db), \
         patch("src.auth.identity.router.run_db", side_effect=fake_run_db):
        client = _mount()
        resp = client.post(
            "/scim/v2/Users",
            json={"userName": "bob@example.com", "active": False},
            headers=_auth_headers(),
        )
    assert resp.status_code == 201
    # _to_scim derives active from row.status — a row created as deprovisioned
    # must surface as active=false in the SCIM response.
    assert resp.json()["active"] is False




def test_get_user_by_id_returns_404_when_missing():
    cfg = _enabled_cfg()

    auth_calls = {"n": 0}

    def fake_run_db(coro_fn):
        auth_calls["n"] += 1
        if auth_calls["n"] == 1:
            return cfg
        return None

    with patch("src.auth.identity.auth.run_db", side_effect=fake_run_db), \
         patch("src.auth.identity.router.run_db", side_effect=fake_run_db):
        client = _mount()
        resp = client.get("/scim/v2/Users/missing-id", headers=_auth_headers())
    assert resp.status_code == 404
    assert resp.json()["status"] == "404"


def test_get_user_by_id_returns_scim_shape():
    cfg = _enabled_cfg()
    row = _user("u-1", "carol@example.com")

    auth_calls = {"n": 0}

    def fake_run_db(coro_fn):
        auth_calls["n"] += 1
        if auth_calls["n"] == 1:
            return cfg
        return row

    with patch("src.auth.identity.auth.run_db", side_effect=fake_run_db), \
         patch("src.auth.identity.router.run_db", side_effect=fake_run_db):
        client = _mount()
        resp = client.get("/scim/v2/Users/u-1", headers=_auth_headers())
    assert resp.status_code == 200
    body = resp.json()
    assert body["id"] == "u-1"
    assert body["userName"] == "carol@example.com"
    assert body["active"] is True


def test_list_users_unsupported_filter_returns_400_invalidfilter():
    cfg = _enabled_cfg()

    auth_calls = {"n": 0}

    def fake_run_db(coro_fn):
        auth_calls["n"] += 1
        if auth_calls["n"] == 1:
            return cfg
        return None  # router signals invalid filter via None return

    with patch("src.auth.identity.auth.run_db", side_effect=fake_run_db), \
         patch("src.auth.identity.router.run_db", side_effect=fake_run_db):
        client = _mount()
        resp = client.get(
            '/scim/v2/Users?filter=displayName eq "x"',
            headers=_auth_headers(),
        )
    assert resp.status_code == 400
    assert resp.json()["scimType"] == "invalidFilter"


def test_list_users_returns_list_response_envelope():
    cfg = _enabled_cfg()
    body = {
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
        "totalResults": 2,
        "startIndex": 1,
        "itemsPerPage": 2,
        "Resources": [
            {"schemas": [], "id": "u-1", "userName": "a", "active": True, "emails": [],
             "meta": {"resourceType": "User", "location": ""}},
            {"schemas": [], "id": "u-2", "userName": "b", "active": True, "emails": [],
             "meta": {"resourceType": "User", "location": ""}},
        ],
    }

    auth_calls = {"n": 0}

    def fake_run_db(coro_fn):
        auth_calls["n"] += 1
        if auth_calls["n"] == 1:
            return cfg
        return body

    with patch("src.auth.identity.auth.run_db", side_effect=fake_run_db), \
         patch("src.auth.identity.router.run_db", side_effect=fake_run_db):
        client = _mount()
        resp = client.get("/scim/v2/Users", headers=_auth_headers())
    assert resp.status_code == 200
    assert resp.json()["totalResults"] == 2


def test_list_users_rejects_count_above_limit():
    # Query validation: count is capped at 200 by FastAPI Query(le=200).
    with patch("src.auth.identity.auth.run_db", return_value=_enabled_cfg()):
        client = _mount()
        resp = client.get("/scim/v2/Users?count=999", headers=_auth_headers())
    assert resp.status_code == 422




def test_put_user_returns_404_when_missing():
    cfg = _enabled_cfg()

    auth_calls = {"n": 0}

    def fake_run_db(coro_fn):
        auth_calls["n"] += 1
        if auth_calls["n"] == 1:
            return cfg
        return ("missing", None)

    with patch("src.auth.identity.auth.run_db", side_effect=fake_run_db), \
         patch("src.auth.identity.router.run_db", side_effect=fake_run_db):
        client = _mount()
        resp = client.put(
            "/scim/v2/Users/missing-id",
            json={"userName": "x@example.com", "active": True},
            headers=_auth_headers(),
        )
    assert resp.status_code == 404


def test_put_user_replaces_username_email_and_status():
    cfg = _enabled_cfg()
    # Simulate the router mutating and returning the row.
    row = _user("u-1", "old@example.com", "old@example.com")
    row.status = "active"

    def runner_after_mutation(*_args, **_kwargs):
        return _make_post_put_row(
            id_="u-1", username="new@example.com", email="new@example.com", status="deprovisioned",
        )

    auth_calls = {"n": 0}

    def fake_run_db(coro_fn):
        auth_calls["n"] += 1
        if auth_calls["n"] == 1:
            return cfg
        return ("ok", runner_after_mutation())

    with patch("src.auth.identity.auth.run_db", side_effect=fake_run_db), \
         patch("src.auth.identity.router.run_db", side_effect=fake_run_db):
        client = _mount()
        resp = client.put(
            "/scim/v2/Users/u-1",
            json={
                "userName": "new@example.com",
                "emails": [{"value": "new@example.com"}],
                "active": False,
            },
            headers=_auth_headers(),
        )
    assert resp.status_code == 200
    body = resp.json()
    assert body["userName"] == "new@example.com"
    assert body["active"] is False


def _make_post_put_row(
    id_: str,
    username: str,
    email: str,
    status: str,
    scim_managed: bool = True,
) -> User:
    u = User()
    u.id = id_
    u.username = username
    u.email = email
    u.status = status
    u.role_id = None
    u.password_hash = ""
    u.scim_managed = scim_managed
    return u


def test_patch_user_replace_active_bool_value_deprovisions():
    cfg = _enabled_cfg()
    row = _user("u-pat", "p@example.com", status="deprovisioned")

    auth_calls = {"n": 0}

    def fake_run_db(coro_fn):
        auth_calls["n"] += 1
        if auth_calls["n"] == 1:
            return cfg
        return ("ok", row)

    with patch("src.auth.identity.auth.run_db", side_effect=fake_run_db), \
         patch("src.auth.identity.router.run_db", side_effect=fake_run_db):
        client = _mount()
        resp = client.patch(
            "/scim/v2/Users/u-pat",
            json={"Operations": [{"op": "replace", "path": "active", "value": False}]},
            headers=_auth_headers(),
        )
    assert resp.status_code == 200
    assert resp.json()["active"] is False


def test_patch_user_returns_404_when_missing():
    cfg = _enabled_cfg()

    auth_calls = {"n": 0}

    def fake_run_db(coro_fn):
        auth_calls["n"] += 1
        if auth_calls["n"] == 1:
            return cfg
        return ("missing", None)

    with patch("src.auth.identity.auth.run_db", side_effect=fake_run_db), \
         patch("src.auth.identity.router.run_db", side_effect=fake_run_db):
        client = _mount()
        resp = client.patch(
            "/scim/v2/Users/missing-id",
            json={"Operations": [{"op": "replace", "value": {"active": True}}]},
            headers=_auth_headers(),
        )
    assert resp.status_code == 404




def test_delete_user_returns_204_when_present():
    cfg = _enabled_cfg()

    auth_calls = {"n": 0}

    def fake_run_db(coro_fn):
        auth_calls["n"] += 1
        if auth_calls["n"] == 1:
            return cfg
        return "ok"

    with patch("src.auth.identity.auth.run_db", side_effect=fake_run_db), \
         patch("src.auth.identity.router.run_db", side_effect=fake_run_db):
        client = _mount()
        resp = client.delete("/scim/v2/Users/u-del", headers=_auth_headers())
    assert resp.status_code == 204
    assert resp.content == b""


def test_delete_user_returns_404_when_missing():
    cfg = _enabled_cfg()

    auth_calls = {"n": 0}

    def fake_run_db(coro_fn):
        auth_calls["n"] += 1
        if auth_calls["n"] == 1:
            return cfg
        return "missing"

    with patch("src.auth.identity.auth.run_db", side_effect=fake_run_db), \
         patch("src.auth.identity.router.run_db", side_effect=fake_run_db):
        client = _mount()
        resp = client.delete("/scim/v2/Users/nope", headers=_auth_headers())
    assert resp.status_code == 404




def test_groups_get_returns_501_with_scim_error_shape():
    with patch("src.auth.identity.auth.run_db", return_value=_enabled_cfg()):
        client = _mount()
        resp = client.get("/scim/v2/Groups", headers=_auth_headers())
    assert resp.status_code == 501
    body = resp.json()
    assert body["status"] == "501"


def test_groups_post_put_patch_delete_all_return_501():
    with patch("src.auth.identity.auth.run_db", return_value=_enabled_cfg()):
        client = _mount()
        # Each verb against the Groups endpoint must be locked at 501.
        for verb, fn in [
            ("POST", client.post),
            ("PUT", client.put),
            ("PATCH", client.patch),
            ("DELETE", client.delete),
        ]:
            kwargs = {"headers": _auth_headers()}
            if verb in ("POST", "PUT", "PATCH"):
                kwargs["json"] = {"displayName": "x"}
            resp = fn("/scim/v2/Groups", **kwargs)
            assert resp.status_code == 501, f"{verb} returned {resp.status_code}"


def test_groups_subpath_locked_at_501():
    with patch("src.auth.identity.auth.run_db", return_value=_enabled_cfg()):
        client = _mount()
        resp = client.get("/scim/v2/Groups/some-group-id", headers=_auth_headers())
    assert resp.status_code == 501


def test_put_user_refuses_to_mutate_non_scim_managed_row():
    cfg = _enabled_cfg()

    auth_calls = {"n": 0}

    def fake_run_db(coro_fn):
        auth_calls["n"] += 1
        if auth_calls["n"] == 1:
            return cfg
        # Router signals refusal via this tuple.
        return ("not_managed", None)

    with patch("src.auth.identity.auth.run_db", side_effect=fake_run_db), \
         patch("src.auth.identity.router.run_db", side_effect=fake_run_db):
        client = _mount()
        resp = client.put(
            "/scim/v2/Users/local-admin",
            json={"userName": "admin", "active": False},
            headers=_auth_headers(),
        )
    assert resp.status_code == 409
    body = resp.json()
    assert body["scimType"] == "mutability"
    # Message must not disclose the per-row SCIM-managed flag (info-leak).
    assert "SCIM-managed" not in body["detail"]


def test_patch_user_refuses_to_mutate_non_scim_managed_row():
    cfg = _enabled_cfg()

    auth_calls = {"n": 0}

    def fake_run_db(coro_fn):
        auth_calls["n"] += 1
        if auth_calls["n"] == 1:
            return cfg
        return ("not_managed", None)

    with patch("src.auth.identity.auth.run_db", side_effect=fake_run_db), \
         patch("src.auth.identity.router.run_db", side_effect=fake_run_db):
        client = _mount()
        resp = client.patch(
            "/scim/v2/Users/local-admin",
            json={"Operations": [{"op": "replace", "path": "active", "value": False}]},
            headers=_auth_headers(),
        )
    assert resp.status_code == 409
    assert resp.json()["scimType"] == "mutability"


def test_delete_user_refuses_to_mutate_non_scim_managed_row():
    cfg = _enabled_cfg()

    auth_calls = {"n": 0}

    def fake_run_db(coro_fn):
        auth_calls["n"] += 1
        if auth_calls["n"] == 1:
            return cfg
        return "not_managed"

    with patch("src.auth.identity.auth.run_db", side_effect=fake_run_db), \
         patch("src.auth.identity.router.run_db", side_effect=fake_run_db):
        client = _mount()
        resp = client.delete("/scim/v2/Users/local-admin", headers=_auth_headers())
    assert resp.status_code == 409
    assert resp.json()["scimType"] == "mutability"


def test_post_user_persists_scim_managed_true_on_real_db(db_session):
    """End-to-end create through the live router — confirms the new column
    is populated and the row is reachable in subsequent SCIM lookups.
    """
    from sqlalchemy import delete, select
    from src.db.helpers import run_db as real_run_db

    real_run_db(_seed_enabled_scim_config)

    created_username = f"scim-c3-{os.urandom(4).hex()}@example.com"

    try:
        client = _mount()
        resp = client.post(
            "/scim/v2/Users",
            json={
                "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
                "userName": created_username,
                "emails": [{"value": created_username, "primary": True}],
                "active": True,
            },
            headers=_auth_headers(),
        )
        assert resp.status_code == 201, resp.text
        created_id = resp.json()["id"]

        async def _check(session):
            row = (
                await session.execute(select(User).where(User.id == created_id))
            ).scalar_one()
            return row.scim_managed, row.status

        scim_managed, status = real_run_db(_check)
        assert scim_managed is True
        assert status == "active"
    finally:
        async def _cleanup(session):
            await session.execute(delete(User).where(User.username == created_username))

        real_run_db(_cleanup)


def test_patch_user_op_remove_on_active_soft_deletes_db_backed(db_session):
    """Drive the live PATCH handler against a real DB row so the
    op:"remove" branch is exercised end-to-end.
    """
    from sqlalchemy import delete, select
    from src.db.helpers import run_db as real_run_db

    uniq = os.urandom(4).hex()
    user_id = f"c5-{uniq}"
    username = f"c5-{uniq}@example.com"

    async def _seed(session):
        await _seed_enabled_scim_config(session)
        session.add(User(
            id=user_id,
            username=username,
            email=username,
            password_hash="",
            status="active",
            scim_managed=True,
        ))

    real_run_db(_seed)

    try:
        client = _mount()
        resp = client.patch(
            f"/scim/v2/Users/{user_id}",
            json={"Operations": [{"op": "remove", "path": "active"}]},
            headers=_auth_headers(),
        )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        # Tombstone semantics: row still exists, but surfaces as active=false.
        assert body["active"] is False
        assert body["id"] == user_id

        async def _check(session):
            row = (
                await session.execute(select(User).where(User.id == user_id))
            ).scalar_one()
            return row.status

        assert real_run_db(_check) == "deprovisioned"
    finally:
        async def _cleanup(session):
            await session.execute(delete(User).where(User.id == user_id))

        real_run_db(_cleanup)


def test_put_user_on_non_scim_managed_returns_409_db_backed(db_session):
    """A non-SCIM-managed user (e.g. created locally) must not be replaceable via
    SCIM — drive PUT against a real row so the mutability gate is exercised
    end-to-end, not just through mocked run_db return paths.
    """
    from sqlalchemy import delete, select
    from src.db.helpers import run_db as real_run_db

    uniq = os.urandom(4).hex()
    user_id = f"c3-put-{uniq}"
    username = f"c3-put-{uniq}@example.com"

    async def _seed(session):
        await _seed_enabled_scim_config(session)
        session.add(User(
            id=user_id,
            username=username,
            email=username,
            password_hash="",
            status="active",
            scim_managed=False,  # locally-managed; SCIM must refuse to mutate
        ))

    real_run_db(_seed)

    try:
        client = _mount()
        resp = client.put(
            f"/scim/v2/Users/{user_id}",
            json={
                "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
                "userName": username,
                "emails": [{"value": username, "primary": True}],
                "active": True,
            },
            headers=_auth_headers(),
        )
        assert resp.status_code == 409, resp.text
        assert resp.json().get("scimType") == "mutability"

        async def _check(session):
            row = (
                await session.execute(select(User).where(User.id == user_id))
            ).scalar_one()
            return row.scim_managed, row.status

        # Gate held: the row is untouched.
        assert real_run_db(_check) == (False, "active")
    finally:
        async def _cleanup(session):
            await session.execute(delete(User).where(User.id == user_id))

        real_run_db(_cleanup)


def test_list_users_excludes_deprovisioned_rows_db_backed(db_session):
    """The list endpoint must hide tombstoned users; GET /Users/{id} can
    still return them with active=false (locked tombstone semantics).
    """
    from sqlalchemy import delete, select
    from src.db.helpers import run_db as real_run_db
    from src.db.models import ScimConfig

    uniq = os.urandom(4).hex()
    active_username = f"c6-active-{uniq}@example.com"
    tomb_username = f"c6-tomb-{uniq}@example.com"
    active_id = f"c6-act-{uniq}"
    tomb_id = f"c6-tomb-{uniq}"

    async def _seed(session):
        existing = (
            await session.execute(select(ScimConfig).where(ScimConfig.id == 1))
        ).scalar_one_or_none()
        if existing is None:
            session.add(_enabled_cfg())
        else:
            existing.enabled = True
            existing.token_hash = _TOKEN_HASH
        session.add(User(
            id=active_id,
            username=active_username,
            email=active_username,
            password_hash="",
            status="active",
            scim_managed=True,
        ))
        session.add(User(
            id=tomb_id,
            username=tomb_username,
            email=tomb_username,
            password_hash="",
            status="deprovisioned",
            scim_managed=True,
        ))

    real_run_db(_seed)

    try:
        client = _mount()
        resp = client.get(
            f'/scim/v2/Users?filter=userName eq "{tomb_username}"',
            headers=_auth_headers(),
        )
        assert resp.status_code == 200
        body = resp.json()
        # Tombstone filtered out of the list.
        assert body["totalResults"] == 0
        assert body["Resources"] == []

        # But the active sibling shows up.
        resp2 = client.get(
            f'/scim/v2/Users?filter=userName eq "{active_username}"',
            headers=_auth_headers(),
        )
        assert resp2.status_code == 200
        assert resp2.json()["totalResults"] == 1

        # And GET /Users/{id} on the tombstoned row still returns it with
        # active=false — locked tombstone read semantics.
        resp3 = client.get(f"/scim/v2/Users/{tomb_id}", headers=_auth_headers())
        assert resp3.status_code == 200
        assert resp3.json()["active"] is False
    finally:
        async def _cleanup(session):
            await session.execute(
                delete(User).where(User.id.in_([active_id, tomb_id]))
            )

        real_run_db(_cleanup)
