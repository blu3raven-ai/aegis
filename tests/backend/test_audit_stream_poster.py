import asyncio


def test_poster_advances_cursor_on_success(monkeypatch):
    monkeypatch.setenv("AEGIS_SECRET_ENCRYPTION_KEY", "FAjK_lhsKHqBJ4uYY3oRWAa7c1pTkbHIfk7gjhFCpx8=")
    from datetime import datetime, timezone
    from sqlalchemy import select
    from src.db.helpers import run_db
    from src.db.models import AuditEvent, AuditStreamConfig
    from src.audit_stream import poster
    from src.security.crypto import encrypt

    seeded = {}

    async def _seed(session):
        row = (await session.execute(select(AuditStreamConfig).where(AuditStreamConfig.id == 1))).scalar_one()
        row.enabled = True
        row.target_type = "webhook"
        row.endpoint_url = "https://hook.example.com/x"
        row.auth_token_enc = encrypt("t")
        row.last_event_id = 0
        evt = AuditEvent(
            created_at=datetime.now(timezone.utc),
            action="test.poster",
            resource_type="user",
            resource_id="u-1",
        )
        session.add(evt)
        await session.flush()
        seeded["event_id"] = evt.id

    run_db(_seed)

    async def fake_webhook(url, token, events, transport=None):
        return {"ok": True, "error": None}

    monkeypatch.setattr(poster, "webhook_deliver", fake_webhook)

    result = asyncio.run(poster.deliver_batch_once())
    assert result["delivered"] >= 1

    async def _read(session):
        row = (await session.execute(select(AuditStreamConfig).where(AuditStreamConfig.id == 1))).scalar_one()
        return row.last_event_id, row.last_error
    last_id, last_error = run_db(_read)
    assert last_id >= seeded["event_id"]
    assert last_error is None


def test_poster_skips_when_disabled(monkeypatch):
    monkeypatch.setenv("AEGIS_SECRET_ENCRYPTION_KEY", "FAjK_lhsKHqBJ4uYY3oRWAa7c1pTkbHIfk7gjhFCpx8=")
    from sqlalchemy import select
    from src.db.helpers import run_db
    from src.db.models import AuditStreamConfig
    from src.audit_stream.poster import deliver_batch_once

    async def _seed(session):
        row = (await session.execute(select(AuditStreamConfig).where(AuditStreamConfig.id == 1))).scalar_one()
        row.enabled = False
    run_db(_seed)

    result = asyncio.run(deliver_batch_once())
    assert result == {"delivered": 0, "skipped": True}
