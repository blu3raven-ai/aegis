"""Decision-row writer for the auto-dismiss matcher.

The matcher orchestrates rule evaluation; this module owns the database
mutation that causes the lifecycle to treat an incoming finding as dismissed.

We write only the Decision row here, not the FindingEvent — at the moment
the matcher runs the finding row may not yet exist (incoming scan), so there
is no ``finding_id`` to attach an event to. The lifecycle caller (commit 7)
writes the FindingEvent with the matched-conditions snapshot once the finding
row is created.
"""
from __future__ import annotations

from sqlalchemy.ext.asyncio import AsyncSession

from src.rules.rate_alarm import auto_dismiss_event_actor
from src.shared.finding_queries import upsert_decision


async def write_auto_dismiss_decision(
    session: AsyncSession,
    *,
    tool: str,
    org: str,
    identity_key: str,
    rule_id: str,
    rule_name: str,
    asset_id: str | None = None,
) -> None:
    """Upsert the Decision row that flags this finding as auto-dismissed.

    ``decided_by`` is namespaced as ``auto-rule:<rule_id>`` so audit queries
    can distinguish rule-driven dismissals from human dismissals without
    parsing the reason string.
    """
    await upsert_decision(
        session,
        tool=tool,
        asset_id=asset_id,
        identity_key=identity_key,
        status="dismissed",
        reason="Auto-dismissed by rule",
        comment=f"Rule: {rule_name}",
        decided_by=auto_dismiss_event_actor(rule_id),
    )


__all__ = ["write_auto_dismiss_decision"]
