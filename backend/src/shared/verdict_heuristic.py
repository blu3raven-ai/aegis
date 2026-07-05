"""Heuristic confidence verdict for findings, used until the LLM Service verifies them.

A finding's ``verdict`` (confidence) is normally written by the LLM verification
pass. When no verifier is configured, every verdict is NULL and the UI's
Confidence column reads "Unrated". This module derives a *provisional* verdict
from signals already present at ingest so the column carries a usable signal
before verification runs. The verifier always wins — the heuristic only ever
seeds a NULL verdict and is overwritten the moment a real verdict arrives.

Mapping (orthogonal to severity — confidence is "how sure", not "how bad"):
  - scanner reports "high" confidence, OR the finding carries a CVE
        -> ``needs_verify``  (plausible; needs the context a scan can't see)
  - otherwise
        -> ``possible``      (low-confidence; kept because the bug class matters)

It deliberately never returns ``confirmed`` — that means a concrete exploit was
articulated, which only Argus (or real-world exploitation evidence) can assert.

`heuristic_verdict` (pure) and `recompute_finding_verdicts` (one SQL UPDATE for
backfill) must stay in sync — both encode the same mapping.
"""
from __future__ import annotations

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession


def heuristic_verdict(scanner_confidence: str | None, *, has_cve: bool) -> str:
    """Return a provisional verdict ('needs_verify' | 'possible')."""
    if (scanner_confidence or "").strip().lower() == "high" or has_cve:
        return "needs_verify"
    return "possible"


async def recompute_finding_verdicts(
    session: AsyncSession,
    *,
    asset_ids: list[str] | None = None,
) -> int:
    """Seed the heuristic verdict on findings that don't have one yet.

    Only touches rows where ``verdict IS NULL`` — an Argus (or prior) verdict is
    never overwritten. Returns rows touched. Callers may scope to ``asset_ids``;
    when omitted, all NULL-verdict findings are seeded.
    """
    if asset_ids is not None and len(asset_ids) == 0:
        return 0

    where = ["f.verdict IS NULL"]
    params: dict = {}
    if asset_ids:
        where.append("f.asset_id = ANY(:asset_ids)")
        params["asset_ids"] = asset_ids

    sql = text(f"""
        UPDATE findings AS f
        SET verdict = CASE
            WHEN LOWER(TRIM(COALESCE(f.detail->>'confidence', ''))) = 'high' THEN 'needs_verify'
            WHEN f.cve_id IS NOT NULL THEN 'needs_verify'
            ELSE 'possible'
        END
        WHERE {' AND '.join(where)}
    """)
    result = await session.execute(sql, params)
    return result.rowcount or 0
