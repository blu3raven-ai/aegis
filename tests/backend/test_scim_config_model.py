def test_scim_config_singleton_seeded():
    from sqlalchemy import select
    from src.db.helpers import run_db
    from src.db.models import ScimConfig

    async def _q(session):
        return (await session.execute(select(ScimConfig).where(ScimConfig.id == 1))).scalar_one_or_none()

    row = run_db(_q)
    assert row is not None
    assert row.id == 1
    assert row.enabled is False
    assert row.token_hash is None
    assert row.default_role_id is None
