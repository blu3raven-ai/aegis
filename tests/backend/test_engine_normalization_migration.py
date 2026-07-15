import pytest
from sqlalchemy import text


@pytest.mark.asyncio
async def test_pre_joern_engine_rows_normalized(db_session):
    # The test DB already has ck_findings_engine enforced via create_all.
    # To simulate pre-migration rows we temporarily drop the constraint,
    # insert the legacy values, apply the normalization UPDATE (which is what
    # the migration does), then restore the constraint and verify the rows
    # are now compliant.
    await db_session.execute(text(
        "ALTER TABLE findings DROP CONSTRAINT IF EXISTS ck_findings_engine"
    ))
    await db_session.commit()

    try:
        await db_session.execute(text(
            "INSERT INTO findings "
            "  (tool, identity_key, state, engine, first_seen_at, last_seen_at, created_at, updated_at, detail) "
            "VALUES "
            "  ('code', 'key-joern',   'open', 'joern',   NOW(), NOW(), NOW(), NOW(), '{}'), "
            "  ('code', 'key-both',    'open', 'both',    NOW(), NOW(), NOW(), NOW(), '{}'), "
            "  ('code', 'key-semgrep', 'open', 'semgrep', NOW(), NOW(), NOW(), NOW(), '{}'), "
            "  ('code', 'key-byo',    'open', 'byo',    NOW(), NOW(), NOW(), NOW(), '{}')"
        ))
        await db_session.commit()

        # Apply the normalization logic from the migration.
        await db_session.execute(text(
            "UPDATE findings SET engine = NULL "
            "WHERE engine IS NOT NULL AND engine NOT IN ('semgrep', 'byo')"
        ))
        await db_session.commit()

        rows = await db_session.execute(
            text(
                "SELECT identity_key, engine FROM findings "
                "WHERE identity_key IN ('key-joern', 'key-both', 'key-semgrep', 'key-byo') "
                "ORDER BY identity_key"
            )
        )
        results = {row.identity_key: row.engine for row in rows}

        assert results["key-joern"] is None
        assert results["key-both"] is None
        assert results["key-semgrep"] == "semgrep"
        assert results["key-byo"] == "byo"
    finally:
        # Clean up inserted rows and restore the constraint so other tests
        # are not affected.
        await db_session.execute(
            text(
                "DELETE FROM findings "
                "WHERE identity_key IN ('key-joern', 'key-both', 'key-semgrep', 'key-byo')"
            )
        )
        await db_session.execute(text(
            "ALTER TABLE findings ADD CONSTRAINT ck_findings_engine "
            "CHECK (engine IS NULL OR engine IN ('semgrep', 'byo'))"
        ))
        await db_session.commit()
