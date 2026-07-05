"""In-app notification producers for user-facing events.

Each producer runs on the caller's existing async session so the notification
is written in the same transaction as the event that triggered it. Producers
are pref-gated (see `src.notifications.prefs`) and never notify the actor about
their own action.
"""
from __future__ import annotations

import re

from sqlalchemy import select

from src.authz.enforcement.scope import users_with_asset_access
from src.db.models import Finding, User, UserPreferences
from src.notifications.prefs import filter_wanting, wants_notification
from src.notifications.store import insert_notification

# `@handle`: starts alphanumeric, then the username charset.
_MENTION_RE = re.compile(r"@([A-Za-z0-9][A-Za-z0-9._-]*)")


def _finding_label(finding: Finding) -> str:
    return finding.title or finding.identity_key or f"finding #{finding.id}"


async def notify_finding_assigned(
    session,
    *,
    finding: Finding,
    assignee_user_id: str | None,
    previous_assignee: str | None,
    actor_user_id: str,
) -> None:
    """Notify a finding's new assignee that it was assigned to them.

    No-op when the assignment is cleared, unchanged, a self-assignment, or the
    assignee has opted out via `notif_assignments`."""
    if not assignee_user_id:
        return
    if assignee_user_id == previous_assignee or assignee_user_id == actor_user_id:
        return
    if not await wants_notification(
        session, assignee_user_id, UserPreferences.notif_assignments
    ):
        return

    await insert_notification(
        session,
        assignee_user_id,
        notification_type="finding.assigned",
        category="assignment",
        severity="info",
        title="Finding assigned to you",
        message=f"You were assigned {_finding_label(finding)}.",
        context={"findingId": finding.id, "assignedBy": actor_user_id},
        link=f"/findings?finding={finding.id}",
    )


async def notify_comment_mentions(
    session,
    *,
    finding: Finding,
    comment_text: str,
    actor_user_id: str,
) -> None:
    """Notify users @-mentioned in a finding comment.

    Recipients are limited to active users who (a) are actually mentioned by
    `@username`, (b) can see the finding — so a mention never leaks a finding to
    someone outside its scope — and (c) haven't opted out via `notif_mentions`.
    The commenter is never notified about their own mention."""
    handles = {m.group(1) for m in _MENTION_RE.finditer(comment_text or "")}
    if not handles:
        return

    rows = (
        await session.execute(
            select(User.id).where(User.username.in_(handles), User.status == "active")
        )
    ).scalars().all()
    mentioned = {uid for uid in rows if uid != actor_user_id}
    if not mentioned:
        return

    # Fail closed: only notify users who can actually see this finding's asset.
    allowed = await users_with_asset_access(session, finding.asset_id)
    recipients = await filter_wanting(
        session,
        [uid for uid in mentioned if uid in allowed],
        UserPreferences.notif_mentions,
    )

    for user_id in recipients:
        await insert_notification(
            session,
            user_id,
            notification_type="finding.mentioned",
            category="mention",
            severity="info",
            title="You were mentioned",
            message=f"You were mentioned in a comment on {_finding_label(finding)}.",
            context={"findingId": finding.id, "mentionedBy": actor_user_id},
            link=f"/findings?finding={finding.id}",
        )


async def notify_kev_affected_users(session, cve_ids: list[str]) -> int:
    """Notify users whose repos have open findings on newly KEV-listed CVEs.

    One aggregated notification per user (a count), gated by `notif_kev` and
    scoped so a user only hears about CVEs affecting assets they can see.
    Returns the number of users notified."""
    if not cve_ids:
        return 0

    rows = (
        await session.execute(
            select(Finding.cve_id, Finding.asset_id)
            .where(
                Finding.cve_id.in_(cve_ids),
                Finding.asset_id.is_not(None),
                Finding.state == "open",
            )
            .distinct()
        )
    ).all()
    if not rows:
        return 0

    # Aggregate the affected CVEs per user, resolving each asset's audience once.
    access_by_asset: dict[str, set[str]] = {}
    cves_by_user: dict[str, set[str]] = {}
    for cve_id, asset_id in rows:
        if asset_id not in access_by_asset:
            access_by_asset[asset_id] = await users_with_asset_access(session, asset_id)
        for user_id in access_by_asset[asset_id]:
            cves_by_user.setdefault(user_id, set()).add(cve_id)

    recipients = await filter_wanting(
        session, list(cves_by_user), UserPreferences.notif_kev
    )
    for user_id in recipients:
        count = len(cves_by_user[user_id])
        plural = "s" if count != 1 else ""
        verb = "affects" if count == 1 else "affect"
        await insert_notification(
            session,
            user_id,
            notification_type="kev.affects_repo",
            category="kev",
            severity="warning",
            title="New KEV-listed vulnerability in your repos",
            message=(
                f"{count} newly KEV-listed CVE{plural} now {verb} open findings "
                "in your repositories."
            ),
            context={"cveCount": count, "cveIds": sorted(cves_by_user[user_id])[:50]},
            link="/findings?kev=true",
        )
    return len(recipients)
