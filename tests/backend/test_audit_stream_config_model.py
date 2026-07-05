def test_audit_stream_config_singleton_seeded():
    from sqlalchemy import select
    from src.db.helpers import run_db
    from src.db.models import AuditStreamConfig

    async def _q(session):
        return (await session.execute(select(AuditStreamConfig).where(AuditStreamConfig.id == 1))).scalar_one_or_none()

    row = run_db(_q)
    assert row is not None
    assert row.id == 1
    assert row.enabled is False
    assert row.target_type is None
    assert row.endpoint_url is None
    assert row.auth_token_enc is None
    assert row.last_event_id == 0
    assert row.last_success_at is None
    assert row.last_error is None
