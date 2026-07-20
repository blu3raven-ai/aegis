"""Heartbeat must not stomp a concurrent revoke/rotate.

The heartbeat runs continuously and previously did a full read-modify-write of
the runner record, so a heartbeat whose read landed before an admin revoke — but
whose write landed after — resurrected the revoked status and old auth token.
The fix makes the heartbeat a targeted last_heartbeat-only UPDATE. Runs against
testcontainer Postgres.
"""
from __future__ import annotations

import os
from unittest.mock import patch
from uuid import uuid4

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost:5432/test")
os.environ.setdefault("APP_SECRET", "0" * 64)

from sqlalchemy import delete

from src.db.helpers import run_db
from src.db.models import Runner
from src.runner import registry
from src.runner.storage import read_runner, touch_heartbeat, write_runner


def _seed(rid: str) -> None:
    async def _q(session):
        session.add(Runner(id=rid, name=rid, status="approved", auth_token_hash="HASH_APPROVED"))

    run_db(_q)


def _cleanup(rid: str) -> None:
    async def _q(session):
        await session.execute(delete(Runner).where(Runner.id == rid))

    run_db(_q)


def test_touch_heartbeat_leaves_status_and_token_untouched():
    rid = f"rr-{uuid4().hex[:8]}"
    _seed(rid)
    try:
        # A revoke has landed: status flipped, token rotated.
        write_runner({"id": rid, "status": "pending_approval", "authTokenHash": "HASH_ROTATED"})
        touch_heartbeat(rid)
        row = read_runner(rid)
        assert row["status"] == "pending_approval"
        assert row["authTokenHash"] == "HASH_ROTATED"
        assert row["lastHeartbeatAt"]  # was set
    finally:
        _cleanup(rid)


def test_heartbeat_with_stale_read_cannot_resurrect_revoked_runner():
    rid = f"rr-{uuid4().hex[:8]}"
    _seed(rid)
    try:
        stale = read_runner(rid)  # pre-revoke snapshot: approved + HASH_APPROVED
        assert stale["status"] == "approved"

        registry.revoke_runner(rid)  # commits: pending_approval + rotated token
        after = read_runner(rid)
        assert after["status"] == "pending_approval"
        rotated = after["authTokenHash"]
        assert rotated != "HASH_APPROVED"

        # Race: this heartbeat's read happened before the revoke (stale dict),
        # and its write lands after. It must not write status/token back.
        with patch("src.runner.registry.read_runner", return_value=stale):
            registry.heartbeat(rid)

        final = read_runner(rid)
        assert final["status"] == "pending_approval", "revoke was stomped by heartbeat"
        assert final["authTokenHash"] == rotated, "old token resurrected by heartbeat"
    finally:
        _cleanup(rid)
