import pytest


def test_jit_creates_new_user_with_default_role():
    from sqlalchemy import select
    from src.db.helpers import run_db
    from src.db.models import SsoConfig
    from src.auth.sso.jit import jit_or_lookup

    async def _seed(session):
        row = (await session.execute(select(SsoConfig).where(SsoConfig.id == 1))).scalar_one_or_none()
        if row is None:
            row = SsoConfig(id=1)
            session.add(row)
        row.default_role_id = None
    run_db(_seed)

    async def _act(session):
        return await jit_or_lookup(
            session, subject="abc-123", email="new-jit@example.com", protocol="saml",
        )

    user = run_db(_act)
    assert user.email == "new-jit@example.com"
    assert user.sso_subject == "abc-123"
    assert user.sso_protocol == "saml"
    assert user.password_hash == ""
    assert user.status == "active"


def test_jit_attaches_to_existing_email():
    from src.db.helpers import run_db
    from src.db.models import User
    from src.auth.sso.jit import jit_or_lookup

    async def _seed(session):
        existing = User(id="jit-existing", username="alice", email="alice@example.com", status="active")
        session.add(existing)
    run_db(_seed)

    async def _act(session):
        return await jit_or_lookup(
            session, subject="alice-saml-id", email="alice@example.com", protocol="saml",
        )

    user = run_db(_act)
    assert user.id == "jit-existing"
    assert user.sso_subject == "alice-saml-id"
    assert user.sso_protocol == "saml"


def test_jit_rejects_subject_conflict():
    from src.db.helpers import run_db
    from src.db.models import User
    from src.auth.sso.jit import AccountConflict, jit_or_lookup

    async def _seed(session):
        existing = User(
            id="jit-conflict", username="bob", email="bob@example.com",
            status="active",
            sso_subject="bob-other-subject", sso_protocol="saml",
        )
        session.add(existing)
    run_db(_seed)

    async def _act(session):
        return await jit_or_lookup(
            session, subject="bob-NEW-subject", email="bob@example.com", protocol="saml",
        )

    with pytest.raises(AccountConflict):
        run_db(_act)
