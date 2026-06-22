"""Hot-path coverage for the api_keys module.

Every authenticated request flows through `_verify_sync` and (for /api/v1/scans/*
calls) `require_scope_and_source`, so this file is deliberately thorough on
edge cases: malformed headers, expired/revoked keys, DB faults, scope mismatches,
source allowlists, and best-effort `last_used_at` writes.

Tests mock `run_db` so they exercise the helper logic without touching Postgres.
"""
from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost:5432/test")
os.environ.setdefault("RUNNER_ENCRYPTION_KEY", "0" * 64)

from src.auth.credentials.auth import _verify_sync, require_scope_and_source  # noqa: E402
from src.auth.credentials import service  # noqa: E402



def test_verify_returns_none_for_missing_header():
    assert _verify_sync(None) is None


def test_verify_returns_none_for_empty_header():
    assert _verify_sync("") is None


def test_verify_returns_none_for_non_bearer_scheme():
    # Basic auth header must not be treated as an API key
    assert _verify_sync("Basic dXNlcjpwYXNz") is None


def test_verify_returns_none_when_token_missing_ak_prefix():
    # Even with Bearer scheme, only tokens starting with ak_ are API keys
    assert _verify_sync("Bearer jwt.like.value") is None


def test_verify_returns_none_when_db_lookup_raises():
    # A DB outage must surface as 401, not 500
    with patch("src.db.helpers.run_db", side_effect=RuntimeError("db down")):
        assert _verify_sync("Bearer ak_live_anything") is None


def test_verify_returns_none_when_token_not_found():
    with patch("src.db.helpers.run_db", return_value=None):
        assert _verify_sync("Bearer ak_live_nonexistent") is None



def _row(*, token_hash: str, revoked_at=None, expires_at=None):
    return SimpleNamespace(
        id=42,
        token_hash=token_hash,
        scopes=["scan:trigger"],
        allowed_source_ids=None,
        revoked_at=revoked_at,
        expires_at=expires_at,
    )


def test_verify_returns_row_for_valid_token():
    import hashlib
    token = "ak_live_validtoken123"
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    row = _row(token_hash=token_hash)
    with patch("src.db.helpers.run_db", return_value=row):
        result = _verify_sync(f"Bearer {token}")
    assert result is row


def test_verify_rejects_revoked_key():
    import hashlib
    token = "ak_live_revokedtoken"
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    row = _row(
        token_hash=token_hash,
        revoked_at=datetime.now(timezone.utc) - timedelta(hours=1),
    )
    with patch("src.db.helpers.run_db", return_value=row):
        assert _verify_sync(f"Bearer {token}") is None


def test_verify_rejects_expired_key():
    import hashlib
    token = "ak_live_expiredtoken"
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    row = _row(
        token_hash=token_hash,
        expires_at=datetime.now(timezone.utc) - timedelta(minutes=1),
    )
    with patch("src.db.helpers.run_db", return_value=row):
        assert _verify_sync(f"Bearer {token}") is None


def test_verify_accepts_key_with_future_expiry():
    import hashlib
    token = "ak_live_futureexp"
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    row = _row(
        token_hash=token_hash,
        expires_at=datetime.now(timezone.utc) + timedelta(days=30),
    )
    with patch("src.db.helpers.run_db", return_value=row):
        assert _verify_sync(f"Bearer {token}") is row


def test_verify_rejects_when_hash_mismatch_between_lookup_and_row():
    # Defence-in-depth: even if a corrupt DB returns a row whose hash differs
    # from the candidate, hmac.compare_digest must reject it.
    import hashlib
    token = "ak_live_someactualtoken"
    actual_hash = hashlib.sha256(token.encode()).hexdigest()
    row = SimpleNamespace(
        id=1,
        token_hash=actual_hash + "deadbeef",  # corrupted/wrong hash
        scopes=[],
        allowed_source_ids=None,
        revoked_at=None,
        expires_at=None,
    )
    with patch("src.db.helpers.run_db", return_value=row):
        assert _verify_sync(f"Bearer {token}") is None



class _Key:
    def __init__(self, scopes, allowed_source_ids=None):
        self.scopes = scopes
        self.allowed_source_ids = allowed_source_ids


def test_multi_scope_key_grants_each_listed_scope():
    key = _Key(scopes=["scan:trigger", "view_findings"], allowed_source_ids=None)
    assert require_scope_and_source(key, scope="scan:trigger", source_id="x") is None
    assert require_scope_and_source(key, scope="view_findings", source_id="x") is None


def test_require_scope_handles_none_scopes_attribute():
    # An ApiKey with no scopes (legacy row) must deny everything, not crash.
    key = SimpleNamespace(scopes=None, allowed_source_ids=None)
    err = require_scope_and_source(key, scope="scan:trigger", source_id="x")
    assert err == {"error": "missing_scope", "missing_scope": "scan:trigger"}


def test_require_scope_handles_missing_allowed_source_ids_attribute():
    # Older Pydantic view layers may omit the attribute entirely.
    key = SimpleNamespace(scopes=["scan:trigger"])
    assert require_scope_and_source(key, scope="scan:trigger", source_id="x") is None


def test_scope_is_case_sensitive():
    # "scan:trigger" and "Scan:Trigger" are not the same scope
    key = _Key(scopes=["Scan:Trigger"], allowed_source_ids=None)
    err = require_scope_and_source(key, scope="scan:trigger", source_id="x")
    assert err == {"error": "missing_scope", "missing_scope": "scan:trigger"}



def test_generated_token_has_live_prefix_and_min_length():
    token = service._generate_token()
    assert token.startswith("ak_live_")
    assert len(token) >= len("ak_live_") + 16  # comfortable entropy floor


def test_generated_tokens_are_unique_across_calls():
    tokens = {service._generate_token() for _ in range(64)}
    assert len(tokens) == 64


def test_hash_token_is_deterministic_sha256_hex():
    h = service._hash_token("ak_live_xyz")
    assert len(h) == 64
    assert all(c in "0123456789abcdef" for c in h)
    assert h == service._hash_token("ak_live_xyz")



def test_middleware_returns_none_for_invalid_token():
    from src.auth.credentials.middleware import try_api_key_auth

    request = MagicMock()
    request.state = SimpleNamespace()

    async def _verify_returns_none(_):
        return None

    with patch("src.auth.credentials.middleware.verify_api_key", new=_verify_returns_none):
        import asyncio
        result = asyncio.run(try_api_key_auth(request, "bogus"))
    assert result is None
    # state should not be polluted on rejection
    assert not hasattr(request.state, "api_key_id")


def test_middleware_populates_request_state_on_success():
    from src.auth.credentials.middleware import try_api_key_auth

    row = SimpleNamespace(
        id=7,
        scopes=["scan:trigger", "view_findings"],
        allowed_source_ids=["src-a"],
    )
    request = MagicMock()
    request.state = SimpleNamespace()

    async def _noop(_):
        return None

    async def _verify_returns_row(_):
        return row

    with (
        patch("src.auth.credentials.middleware.verify_api_key", new=_verify_returns_row),
        patch("src.auth.credentials.service.record_usage", new=_noop),
    ):
        import asyncio
        result = asyncio.run(try_api_key_auth(request, "ak_live_foo"))

    assert result is row
    assert request.state.user_sub == "api_key:7"
    assert request.state.user_role == "viewer"
    assert request.state.api_key_id == 7
    assert request.state.api_key_scopes == ["scan:trigger", "view_findings"]
    assert request.state.api_key_allowed_source_ids == ["src-a"]


def test_middleware_normalises_empty_allowlist_to_none():
    """An empty allowed_source_ids list means unrestricted; the request state
    must surface None so downstream checks treat it as 'no allowlist set'."""
    from src.auth.credentials.middleware import try_api_key_auth

    row = SimpleNamespace(id=8, scopes=[], allowed_source_ids=[])
    request = MagicMock()
    request.state = SimpleNamespace()

    async def _noop(_):
        return None

    async def _verify_returns_row(_):
        return row

    with (
        patch("src.auth.credentials.middleware.verify_api_key", new=_verify_returns_row),
        patch("src.auth.credentials.service.record_usage", new=_noop),
    ):
        import asyncio
        asyncio.run(try_api_key_auth(request, "ak_live_foo"))

    assert request.state.api_key_allowed_source_ids is None


def test_middleware_record_usage_failure_does_not_block_auth():
    """last_used_at is best-effort — DB write failure must not break auth."""
    from src.auth.credentials.middleware import try_api_key_auth

    row = SimpleNamespace(id=9, scopes=["scan:trigger"], allowed_source_ids=None)
    request = MagicMock()
    request.state = SimpleNamespace()

    async def _boom(_):
        raise RuntimeError("write failed")

    async def _verify_returns_row(_):
        return row

    with (
        patch("src.auth.credentials.middleware.verify_api_key", new=_verify_returns_row),
        patch("src.auth.credentials.service.record_usage", new=_boom),
    ):
        import asyncio
        result = asyncio.run(try_api_key_auth(request, "ak_live_foo"))

    assert result is row
    assert request.state.api_key_id == 9



def test_record_usage_swallows_db_errors():
    """A failed last_used_at write must not raise — auth is the priority."""

    # record_usage now uses native async via get_session(); patch THAT, not the
    # legacy run_db path. Letting it touch the real engine would bind a pool to
    # the transient asyncio.run loop and contaminate later tests.
    def _boom(*_args, **_kwargs):
        raise RuntimeError("db down")

    with patch("src.db.engine.get_session", side_effect=_boom):
        # Should not raise
        import asyncio
        asyncio.run(service.record_usage(123))


def _drive(coro):
    """Run a coroutine on a fresh loop without colliding with an outer loop."""
    import asyncio
    new_loop = asyncio.new_event_loop()
    try:
        return new_loop.run_until_complete(coro)
    finally:
        new_loop.close()


def test_record_usage_updates_last_used_at_when_row_exists():
    captured: dict = {}

    def fake_run_db(coro_fn):
        class _FakeRow:
            last_used_at = None

        row = _FakeRow()

        class _FakeSession:
            async def get(self, _model, _id):
                return row

        _drive(coro_fn(_FakeSession()))
        captured["last_used_at"] = row.last_used_at
        return None

    with patch("src.auth.credentials.service.run_db", side_effect=fake_run_db):
        service._record_usage_sync(123)

    assert isinstance(captured["last_used_at"], datetime)
    assert captured["last_used_at"].tzinfo is not None


def test_record_usage_with_missing_row_is_noop():
    """Recording usage for a deleted/missing key must not raise."""
    def fake_run_db(coro_fn):
        class _FakeSession:
            async def get(self, _model, _id):
                return None

        _drive(coro_fn(_FakeSession()))
        return None

    with patch("src.auth.credentials.service.run_db", side_effect=fake_run_db):
        service._record_usage_sync(999)



def test_create_returns_token_with_expected_format():
    captured = {}

    def fake_run_db(coro_fn):
        from src.auth.credentials.models import ApiKeyRecord

        class _FakeRow:
            id = 1
            name = "ci"
            prefix = "ak_live_"
            last_four = "abcd"
            scopes = ["scan:trigger"]
            created_by = "user-1"
            created_at = datetime.now(timezone.utc)
            last_used_at = None
            expires_at = None
            revoked_at = None

        class _FakeSession:
            def add(self, row):
                captured["row"] = row

            async def flush(self):
                return None

            async def refresh(self, _row):
                return None

        _drive(coro_fn(_FakeSession()))
        return ApiKeyRecord.from_orm(_FakeRow())

    with patch("src.auth.credentials.service.run_db", side_effect=fake_run_db):
        record, token = service._create_sync(
            name="ci", scopes=["scan:trigger"], created_by="u", expires_in_days=None
        )

    assert token.startswith("ak_live_")
    assert record.scopes == ["scan:trigger"]
    # The row staged for insert must include hash + last_four derived from the
    # exact token returned to the caller (no token regeneration).
    staged = captured["row"]
    import hashlib
    assert staged.token_hash == hashlib.sha256(token.encode()).hexdigest()
    assert staged.last_four == token[-4:]


def test_create_with_expiry_sets_future_expires_at():
    captured = {}

    def fake_run_db(coro_fn):
        from src.auth.credentials.models import ApiKeyRecord

        class _FakeSession:
            def add(self, row):
                captured["row"] = row

            async def flush(self):
                return None

            async def refresh(self, _row):
                return None

        class _Out:
            id = 1
            name = ""
            prefix = "ak_live_"
            last_four = "xxxx"
            scopes = []
            created_by = None
            created_at = datetime.now(timezone.utc)
            last_used_at = None
            expires_at = None
            revoked_at = None

        _drive(coro_fn(_FakeSession()))
        return ApiKeyRecord.from_orm(_Out())

    with patch("src.auth.credentials.service.run_db", side_effect=fake_run_db):
        service._create_sync(name="", scopes=[], created_by=None, expires_in_days=7)

    expires_at = captured["row"].expires_at
    delta = expires_at - datetime.now(timezone.utc)
    assert timedelta(days=6, hours=23) < delta < timedelta(days=7, hours=1)



def test_record_to_dict_never_leaks_token_hash():
    from src.auth.credentials.models import ApiKeyRecord
    rec = ApiKeyRecord(
        id=1,
        name="ci",
        prefix="ak_live_",
        last_four="wxyz",
        scopes=["scan:trigger"],
        created_by="u",
        created_at=datetime.now(timezone.utc),
        last_used_at=None,
        expires_at=None,
        revoked_at=None,
    )
    d = rec.to_dict()
    assert "token_hash" not in d
    assert "token" not in d
    assert d["last_four"] == "wxyz"


@pytest.mark.parametrize("dt_field", ["created_at", "last_used_at", "expires_at", "revoked_at"])
def test_record_to_dict_serialises_datetimes_to_iso(dt_field):
    from src.auth.credentials.models import ApiKeyRecord
    now = datetime.now(timezone.utc)
    kwargs = dict(
        id=1, name="", prefix="ak_live_", last_four="...x",
        scopes=[], created_by=None, created_at=now,
        last_used_at=None, expires_at=None, revoked_at=None,
    )
    kwargs[dt_field] = now
    rec = ApiKeyRecord(**kwargs)
    d = rec.to_dict()
    # ISO format always ends with timezone info for tz-aware datetimes
    assert d[dt_field].startswith(now.isoformat()[:19])
