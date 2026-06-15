def test_sso_config_singleton_seeded():
    from sqlalchemy import select
    from src.db.helpers import run_db
    from src.db.models import SsoConfig

    async def _q(session):
        row = (await session.execute(select(SsoConfig).where(SsoConfig.id == 1))).scalar_one_or_none()
        return row

    row = run_db(_q)
    assert row is not None
    assert row.id == 1
    assert row.enabled is False
    assert row.protocol is None
    assert row.default_role_id is None


def test_user_has_sso_columns():
    from src.db.models import User
    assert hasattr(User, "sso_subject")
    assert hasattr(User, "sso_protocol")
