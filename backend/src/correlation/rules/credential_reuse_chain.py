"""Rule 9: Credential reuse — same secret hash in 2+ locations → reuse chain.

When a verified secret hash appears in multiple (repo, file) pairs, the
credential has been copy-pasted. A rotation now requires updating every location;
missing one leaves the credential live. The chain surfaces all instances so the
responder can handle all of them in a single workflow.

Confidence is 0.95 — hash equality means the bytes are identical; the only
residual uncertainty is whether the credential was already rotated but the
finding hasn't been closed yet.
"""
from __future__ import annotations

import logging

from sqlalchemy import select

from src.correlation.rule import RuleContext
from src.db.helpers import run_db
from src.db.models import VerifiedSecret

logger = logging.getLogger(__name__)

_CHAIN_TYPE = "credential_reuse"
_CONFIDENCE = 0.95


def _count_secret_locations(secret_hash: str) -> int:
    """Return the number of distinct (org, repo, file) locations holding this secret hash."""

    async def _query(session):
        result = await session.execute(
            select(VerifiedSecret).where(
                VerifiedSecret.secret_hash == secret_hash,
                VerifiedSecret.status == "verified",
            )
        )
        return result.scalars().all()

    rows = run_db(_query)
    return len(rows)


class CredentialReuseChainRule:
    """Rule 9: Credential reuse across files or repos."""

    triggers: list[str] = ["scan.finding"]
    name: str = "credential_reuse_chain"

    def evaluate(self, event: dict, ctx: RuleContext) -> None:
        payload = event.get("payload", {})
        finding = payload.get("finding", {})
        scanner_type = finding.get("tool") or finding.get("scanner_type", "")
        org = finding.get("org") or event.get("org_id", "")
        finding_id = finding.get("id") or finding.get("finding_id")

        if not org or finding_id is None:
            return
        if scanner_type != "secrets":
            return

        detail = finding.get("detail", {})
        if detail.get("verification_status") != "verified":
            return

        secret_hash = detail.get("secret_hash")
        if not secret_hash:
            return

        # Look up all open secret findings in the org sharing the same hash
        matching = [
            f for f in ctx.state.lookup_open_findings(
                org_id=org,
                scanner_type="secrets",
            )
            if f.get("detail", {}).get("secret_hash") == secret_hash
            and f.get("detail", {}).get("verification_status") == "verified"
            and f["id"] != finding_id
        ]

        if not matching:
            # Also check the verified_secrets table for cross-org or historical reuse
            location_count = _count_secret_locations(secret_hash)
            if location_count < 2:
                return

        logger.warning(
            "credential_reuse_chain: secret hash %s...%s reused in %d location(s); "
            "emitting reuse chain for org %s",
            secret_hash[:6], secret_hash[-4:], len(matching) + 1, org,
        )

        # Stable dedup anchor: same hash in same org → one chain regardless of
        # which finding triggered first.
        dedup_event_id = f"credential_reuse:{org}:{secret_hash}"

        chain_id = ctx.emit.emit_chain(
            {
                "org_id": org,
                "chain_type": _CHAIN_TYPE,
                "severity": "critical",
            },
            source_event_id=dedup_event_id,
            rule_name=self.name,
        )
        if chain_id is None:
            return

        # Add an edge for every known location of the reused credential.
        for other in matching:
            ctx.emit.emit_chain_edge(
                chain_id,
                finding_id,
                other["id"],
                "credential_reused_across_locations",
                confidence=_CONFIDENCE,
                rule_name=self.name,
            )
