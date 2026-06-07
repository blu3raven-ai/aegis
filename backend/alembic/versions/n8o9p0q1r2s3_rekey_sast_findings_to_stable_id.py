"""rekey sast findings to stable identity_key

Revision ID: n8o9p0q1r2s3
Revises: m7n8o9p0q1r2
Create Date: 2026-06-02 00:00:00.000000

Rewrites identity_key for code_scanning findings whose detail.cwe is
non-empty to the engine-agnostic form `{repo}:{file_path}:sast%3Acwe-<n>:{line}`.
Mirrors the surrogate rule_id that joern + opengrep merging now produces
post-PR. Without this rekey, the first post-deploy scan would mark every
existing SAST finding "fixed" and create a parallel row under the new key,
losing dismissals + introduced_by_* attribution.

Identity format is `{repo}:{file_path}:{rule_id}:{start_line}` (see
CodeScanningHooks.compute_identity_key). Internal colons in any segment
are escaped to `%3A`, so the surrogate `sast:cwe-89` is stored as
`sast%3Acwe-89` to preserve the 4-segment shape.

The cwe canonicalization matches `_canonical_cwe` in merge.py:
strip non-`CWE-<n>` suffixes (descriptive text after the CWE id) and
lower-case the result. Rows whose first cwe entry doesn't start with a
`CWE-<n>` token are left untouched.

Existing rows that already share the same (repo, file, cwe, line) under
different rule_ids will collide post-rekey. We resolve collisions by
keeping the oldest row and deleting the duplicates, then rekeying the
survivors.
"""
from typing import Sequence, Union

from alembic import op


revision: str = "n8o9p0q1r2s3"
down_revision: Union[str, Sequence[str], None] = "m7n8o9p0q1r2"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


# chr(37) constructs the literal '%' inside the SQL string itself, so
# the raw migration text passed to the DBAPI driver contains no '%'
# characters at all — this avoids both psycopg2's pyformat marker
# (`%s` / `%(name)s`) and any double-percent escaping concerns.

# Canonical cwe extractor: matches the leading "CWE-<digits>" prefix of
# detail->'cwe'->>0 and lower-cases it. Empty string when the value
# doesn't start with a CWE token.
_CANONICAL_CWE_EXPR = (
    "lower(substring(detail->'cwe'->>0 from "
    "'^(CWE-[0-9]+)'))"
)

# The seven-char prefix we use to detect already-rekeyed rows is the
# literal `sast%3A`; built in SQL via `chr(37)` to keep `%` out of the
# Python string.
_ALREADY_REKEYED_PREFIX = "'sast' || chr(37) || '3A'"


def _new_identity_key_sql() -> str:
    return (
        "split_part(identity_key, ':', 1) "
        "|| ':' || split_part(identity_key, ':', 2) "
        f"|| ':sast' || chr(37) || '3A' || {_CANONICAL_CWE_EXPR} "
        "|| ':' || split_part(identity_key, ':', 4)"
    )


def _rekey_filter_sql() -> str:
    # Rows that are eligible for rekey: code_scanning, have a parseable
    # CWE-<n> in detail->'cwe'->0, and are not already rekeyed.
    return (
        "tool = 'code_scanning' "
        "AND detail ? 'cwe' "
        "AND jsonb_typeof(detail->'cwe') = 'array' "
        "AND jsonb_array_length(detail->'cwe') > 0 "
        f"AND {_CANONICAL_CWE_EXPR} IS NOT NULL "
        f"AND substr(split_part(identity_key, ':', 3), 1, 7) <> {_ALREADY_REKEYED_PREFIX}"
    )


def upgrade() -> None:
    bind = op.get_bind()

    # 1) Drop pre-existing duplicates that would otherwise violate the
    #    unique (tool, org, identity_key) constraint post-rekey.
    #    For each (tool, org, future_identity_key) cohort keep the row
    #    with the lowest id (oldest) and delete the rest. Dismissals on
    #    deleted rows are lost — this is the unavoidable price of
    #    collapsing previously-distinct rule_ids onto one surrogate.
    new_key_expr = _new_identity_key_sql()
    rekey_filter = _rekey_filter_sql()

    # Stage the ids of duplicates we plan to delete so we can wipe
    # dependent rows first (finding_events FK is not ON DELETE CASCADE).
    bind.exec_driver_sql(
        f"""
        CREATE TEMP TABLE _rekey_dupes ON COMMIT DROP AS
        WITH eligible AS (
            SELECT id, tool, org, ({new_key_expr}) AS new_key
            FROM findings
            WHERE {rekey_filter}
        ),
        ranked AS (
            SELECT id,
                   row_number() OVER (
                       PARTITION BY tool, org, new_key
                       ORDER BY id
                   ) AS rn
            FROM eligible
        )
        SELECT id FROM ranked WHERE rn > 1;
        """
    )

    # Delete child rows first to satisfy FK constraints, then the
    # findings themselves. Decisions reference (tool, org, identity_key)
    # rather than finding_id, so their cleanup needs the old keys —
    # capture them before we delete the findings.
    bind.exec_driver_sql(
        """
        DELETE FROM finding_events
        WHERE finding_id IN (SELECT id FROM _rekey_dupes);
        """
    )
    bind.exec_driver_sql(
        """
        DELETE FROM decisions
        WHERE (tool, org, identity_key) IN (
            SELECT tool, org, identity_key
            FROM findings
            WHERE id IN (SELECT id FROM _rekey_dupes)
        );
        """
    )
    bind.exec_driver_sql(
        """
        DELETE FROM findings
        WHERE id IN (SELECT id FROM _rekey_dupes);
        """
    )

    # 2) Rewrite identity_key on the surviving rows.
    bind.exec_driver_sql(
        f"""
        UPDATE findings
        SET identity_key = {new_key_expr}
        WHERE {rekey_filter};
        """
    )


def downgrade() -> None:
    # Per-engine rule_ids varied per finding and aren't recoverable from
    # the rewritten key. Deduplication is also irreversible. Downgrade is
    # a no-op; restore from backup if you need to revert.
    pass
