from sqlalchemy import CheckConstraint

from src.db.models import Finding


def test_verdict_constraint_includes_runtime_verification():
    ck = next(
        c for c in Finding.__table__.constraints
        if isinstance(c, CheckConstraint) and c.name == "ck_findings_verdict"
    )
    assert "needs_runtime_verification" in str(ck.sqltext)
