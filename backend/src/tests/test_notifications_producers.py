"""Unit tests for in-app notification producers."""
from __future__ import annotations

import asyncio
import os
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost:5432/test")
os.environ.setdefault("APP_SECRET", "0" * 64)

from src.db.models import Notification  # noqa: E402
from src.notifications.producers import (  # noqa: E402
    notify_comment_mentions,
    notify_finding_assigned,
    notify_kev_affected_users,
)


class _Session:
    """Mock async session: scripts the pref lookup + retention-count queries and
    records rows passed to add()."""

    def __init__(self, pref_value):
        self.added: list = []
        pref = MagicMock()
        pref.scalar_one_or_none.return_value = pref_value
        count = MagicMock()
        count.scalar.return_value = 1  # under the retention cap → no deletion
        self.execute = AsyncMock(side_effect=[pref, count])

    def add(self, obj):
        self.added.append(obj)

    async def flush(self):
        pass

    async def delete(self, obj):  # pragma: no cover - not hit under the cap
        pass


def _finding(fid: int = 7, title: str | None = "SQL injection in login"):
    return SimpleNamespace(id=fid, title=title, identity_key="abc123", asset_id="asset-1")


def _run(pref_value, **kwargs) -> _Session:
    session = _Session(pref_value)
    asyncio.run(notify_finding_assigned(session, **kwargs))
    return session


def test_notifies_new_assignee_when_pref_enabled():
    session = _run(
        True, finding=_finding(), assignee_user_id="u2", previous_assignee=None, actor_user_id="u1"
    )
    assert len(session.added) == 1
    notif = session.added[0]
    assert isinstance(notif, Notification)
    assert notif.user_id == "u2"
    assert notif.type == "finding.assigned"
    assert notif.link == "/findings?finding=7"
    assert "SQL injection" in notif.message


def test_notifies_when_no_prefs_row_defaults_on():
    session = _run(
        None, finding=_finding(), assignee_user_id="u2", previous_assignee=None, actor_user_id="u1"
    )
    assert len(session.added) == 1


def test_no_notification_on_self_assignment():
    session = _run(
        True, finding=_finding(), assignee_user_id="u1", previous_assignee=None, actor_user_id="u1"
    )
    assert session.added == []
    session.execute.assert_not_called()


def test_no_notification_when_cleared():
    session = _run(
        True, finding=_finding(), assignee_user_id=None, previous_assignee="u2", actor_user_id="u1"
    )
    assert session.added == []


def test_no_notification_when_unchanged():
    session = _run(
        True, finding=_finding(), assignee_user_id="u2", previous_assignee="u2", actor_user_id="u1"
    )
    assert session.added == []


def test_no_notification_when_pref_disabled():
    session = _run(
        False, finding=_finding(), assignee_user_id="u2", previous_assignee=None, actor_user_id="u1"
    )
    assert session.added == []


# ── mentions ────────────────────────────────────────────────────────────────


def _scalars(items):
    r = MagicMock()
    r.scalars.return_value.all.return_value = items
    return r


def _rows(rows):
    r = MagicMock()
    r.all.return_value = rows
    return r


def _scalar(value):
    r = MagicMock()
    r.scalar.return_value = value
    return r


class _ScriptedSession:
    """Async session whose execute() returns pre-scripted results in order."""

    def __init__(self, results):
        self.added: list = []
        self.execute = AsyncMock(side_effect=results)

    def add(self, obj):
        self.added.append(obj)

    async def flush(self):
        pass

    async def delete(self, obj):  # pragma: no cover
        pass


def _run_mentions(results, *, comment_text, actor_user_id="u1"):
    session = _ScriptedSession(results)
    asyncio.run(
        notify_comment_mentions(
            session,
            finding=_finding(),
            comment_text=comment_text,
            actor_user_id=actor_user_id,
        )
    )
    return session


def test_mention_notifies_in_scope_user_with_pref_on():
    session = _run_mentions(
        [
            _scalars(["u2"]),          # resolve @bob -> u2
            _scalars([]),              # admins
            _scalars(["u2"]),          # direct grant on the asset
            _scalars([]),              # team grants
            _scalars(["u2"]),          # active-user filter
            _rows([("u2", True)]),     # notif_mentions enabled
            _scalar(1),                # retention count
        ],
        comment_text="hey @bob take a look",
    )
    assert len(session.added) == 1
    notif = session.added[0]
    assert notif.user_id == "u2"
    assert notif.type == "finding.mentioned"
    assert notif.link == "/findings?finding=7"


def test_mention_with_no_handles_is_noop():
    session = _run_mentions([], comment_text="no handles here")
    assert session.added == []
    session.execute.assert_not_called()


def test_self_mention_is_skipped():
    session = _run_mentions(
        [_scalars(["u1"])],  # only the commenter is mentioned
        comment_text="note to self @me",
        actor_user_id="u1",
    )
    assert session.added == []


def test_out_of_scope_mention_is_not_notified():
    session = _run_mentions(
        [
            _scalars(["u2"]),  # resolve
            _scalars([]),      # admins
            _scalars([]),      # direct
            _scalars([]),      # team  → no access
        ],
        comment_text="@bob heads up",
    )
    assert session.added == []


def test_mention_pref_disabled_is_not_notified():
    session = _run_mentions(
        [
            _scalars(["u2"]),
            _scalars([]),
            _scalars(["u2"]),
            _scalars([]),
            _scalars(["u2"]),        # active-user filter
            _rows([("u2", False)]),  # opted out
        ],
        comment_text="@bob ping",
    )
    assert session.added == []


# ── KEV ──────────────────────────────────────────────────────────────────────


def _run_kev(results, cve_ids):
    session = _ScriptedSession(results)
    asyncio.run(notify_kev_affected_users(session, cve_ids))
    return session


def test_kev_notifies_affected_in_scope_user():
    session = _run_kev(
        [
            _rows([("CVE-1", "asset-1")]),  # open finding on the newly-KEV CVE
            _scalars([]),                    # admins
            _scalars(["u2"]),                # direct grant on asset-1
            _scalars([]),                    # team
            _scalars(["u2"]),                # active-user filter
            _rows([("u2", True)]),           # notif_kev enabled
            _scalar(1),                      # retention count
        ],
        cve_ids=["CVE-1"],
    )
    assert len(session.added) == 1
    notif = session.added[0]
    assert notif.user_id == "u2"
    assert notif.type == "kev.affects_repo"
    assert notif.severity == "warning"
    assert "1 newly KEV-listed CVE " in notif.message
    assert notif.link == "/findings?kev=true"


def test_kev_aggregates_multiple_cves_per_user():
    session = _run_kev(
        [
            _rows([("CVE-1", "asset-1"), ("CVE-2", "asset-1")]),  # two CVEs, one asset
            _scalars([]),                # admins
            _scalars(["u2"]),            # direct (asset-1 resolved once, then cached)
            _scalars([]),                # team
            _scalars(["u2"]),            # active-user filter
            _rows([("u2", True)]),       # pref on
            _scalar(1),                  # retention count
        ],
        cve_ids=["CVE-1", "CVE-2"],
    )
    assert len(session.added) == 1
    assert "2 newly KEV-listed CVEs" in session.added[0].message


def test_kev_no_new_cves_is_noop():
    session = _run_kev([], cve_ids=[])
    assert session.added == []
    session.execute.assert_not_called()


def test_kev_no_affected_findings_is_noop():
    session = _run_kev([_rows([])], cve_ids=["CVE-1"])
    assert session.added == []


def test_kev_pref_disabled_is_not_notified():
    session = _run_kev(
        [
            _rows([("CVE-1", "asset-1")]),
            _scalars([]),
            _scalars(["u2"]),
            _scalars([]),
            _scalars(["u2"]),        # active-user filter
            _rows([("u2", False)]),  # opted out
        ],
        cve_ids=["CVE-1"],
    )
    assert session.added == []


def test_kev_disabled_user_is_not_notified():
    # A user with a direct grant on the asset but a non-active account: the
    # active-user filter drops them, so no KEV notification is produced.
    session = _run_kev(
        [
            _rows([("CVE-1", "asset-1")]),  # open finding on the newly-KEV CVE
            _scalars([]),                    # admins
            _scalars(["u2"]),                # direct grant on asset-1
            _scalars([]),                    # team
            _scalars([]),                    # active-user filter → u2 disabled
        ],
        cve_ids=["CVE-1"],
    )
    assert session.added == []
