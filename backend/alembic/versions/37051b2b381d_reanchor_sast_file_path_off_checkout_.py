"""reanchor sast file_path off checkout prefix

Revision ID: 37051b2b381d
Revises: 25f23cdfe06b
Create Date: 2026-07-03 00:36:14.879629

Data migration. SAST (code_scanning) findings historically stored the raw
semgrep path, which carries the clone's ``<repo>/_checkout/`` scaffolding prefix
(e.g. ``acme-repo/_checkout/app/db.py``). Ingest now re-anchors that to the
repo-relative form (``app/db.py``). Because the SAST identity key embeds
``file_path`` (``{repo}:{file_path}:{rule_id}:{loc}``), the stored key must be
rewritten in lockstep — otherwise the next scan would compute a *new* key for
each existing finding, mark the old one fixed, and re-create it, orphaning its
triage/dismissal decisions. This backfill rewrites ``findings.file_path`` and
``findings.identity_key`` and the matching ``decisions.identity_key`` for the
affected rows, so identity is preserved across the cutover.

The pre-fix key also embedded the ephemeral ``/workspace/job-<hash>/`` clone
prefix, so the same finding scanned twice produced distinct keys — cross-scan
duplicates dedup never collapsed. Re-anchoring converges those keys, which the
``uq_finding_tool_asset_key`` unique constraint forbids; the migration skips
(does not delete) a colliding duplicate, leaving the surviving row clean and
letting the next scan mark the stale-key duplicate fixed. Non-destructive and
idempotent.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '37051b2b381d'
down_revision: Union[str, Sequence[str], None] = '25f23cdfe06b'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_MARKER = "_checkout/"


def _reanchor(path: str) -> str:
    idx = path.rfind(_MARKER)
    return path[idx + len(_MARKER):] if idx != -1 else path


def _esc(value: str) -> str:
    # Mirror code_finding_identity._esc so the rewritten key byte-matches what
    # ingest would now produce for the re-anchored path.
    return str(value).replace(":", "%3A")


def upgrade() -> None:
    conn = op.get_bind()
    # The underscore in "_checkout" is a LIKE wildcard; escape it so the scan
    # matches the literal segment and doesn't waste work on incidental matches.
    # Order most-recent-first so the surviving row of any duplicate set is the
    # latest scan's copy (see the collision handling below).
    rows = conn.execute(
        sa.text(
            "SELECT id, asset_id, file_path, identity_key FROM findings "
            "WHERE tool = 'code_scanning' AND file_path LIKE :pat ESCAPE '\\' "
            "ORDER BY last_seen_at DESC, id DESC"
        ),
        {"pat": "%\\_checkout/%"},
    ).mappings().all()

    for row in rows:
        old_fp = row["file_path"]
        new_fp = _reanchor(old_fp)
        if not new_fp or new_fp == old_fp:
            continue

        old_key = row["identity_key"]
        esc_old = _esc(old_fp)
        # The identity key embeds the escaped file_path as its second component.
        # If it isn't present the key was derived from a different path shape —
        # leave the whole row untouched rather than desync file_path from key;
        # the next scan reconciles it via the Python dedup pass.
        if esc_old not in old_key:
            continue
        new_key = old_key.replace(esc_old, _esc(new_fp), 1)

        # The old identity key embedded the ephemeral "/workspace/job-<hash>/"
        # clone prefix, so the SAME finding scanned twice produced two rows with
        # different keys — cross-scan duplicates that dedup never collapsed.
        # Re-anchoring makes those keys converge, which the uq_finding_tool_asset_key
        # unique constraint forbids. When the clean key is already taken (by a
        # prior row we rewrote, or an existing clean finding), skip this duplicate
        # rather than delete it: the next scan emits the clean key, matches the
        # surviving row, and marks this stale-key row fixed. Non-destructive and
        # idempotent — a re-run finds nothing left to change.
        collides = conn.execute(
            sa.text(
                "SELECT 1 FROM findings "
                "WHERE tool = 'code_scanning' "
                "AND asset_id IS NOT DISTINCT FROM :a "
                "AND identity_key = :k AND id <> :self LIMIT 1"
            ),
            {"a": row["asset_id"], "k": new_key, "self": row["id"]},
        ).scalar()
        if collides:
            continue

        if new_key != old_key:
            # Move any decisions onto the clean key, skipping any that would
            # collide with an already-clean decision for the same (tool, asset)
            # — uq_decision_tool_asset_key forbids duplicates. A skipped stale
            # decision is harmless; it no longer matches any live finding.
            conn.execute(
                sa.text(
                    "UPDATE decisions AS d SET identity_key = :nk "
                    "WHERE d.tool = 'code_scanning' AND d.identity_key = :ok "
                    "AND NOT EXISTS ("
                    "  SELECT 1 FROM decisions AS d2 "
                    "  WHERE d2.tool = 'code_scanning' "
                    "  AND d2.asset_id IS NOT DISTINCT FROM d.asset_id "
                    "  AND d2.identity_key = :nk"
                    ")"
                ),
                {"nk": new_key, "ok": old_key},
            )

        conn.execute(
            sa.text(
                "UPDATE findings SET file_path = :fp, identity_key = :nk WHERE id = :id"
            ),
            {"fp": new_fp, "nk": new_key, "id": row["id"]},
        )


def downgrade() -> None:
    raise NotImplementedError("Forward-only; no downgrade.")
