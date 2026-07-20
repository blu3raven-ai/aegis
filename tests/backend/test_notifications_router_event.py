"""Tests for notifications.router_event.NotificationEventRouter._handle_event.

Covers the highest-blast-radius dispatch path in the notifications subsystem:
  - Filter subscribed event types
  - Resolve destinations from rules OR event_filter
  - Select sender + formatter per destination
  - Record delivery (success or failed) and emit outcome event
  - Rules-vs-event-filter precedence: rules-claim-wins; fallback to event_filter
    if rules exist but none match; legacy event_filter fanout if no rules at all

DB-backed: destinations and rules live in Postgres so we exercise the real
get_enabled_destinations / get_active_rules / record_delivery code paths. Only
the per-type senders are faked so we don't issue real HTTP/SMTP.
"""
from __future__ import annotations

from typing import Any
from uuid import uuid4

import pytest
import pytest_asyncio
from sqlalchemy import delete as sa_delete, select

from src.connectors.base import SendResult
from src.db.models import (
    NotificationDelivery,
    NotificationDestination,
    NotificationRule,
)
from src.notifications.destination import read_config_secret
from src.notifications.router_event import NotificationEventRouter
from src.shared.event_bus import Event




class _FakeSender:
    """Records every send call and returns a configurable SendResult.

    Used by patching the sender symbols on the senders modules; the deferred
    imports inside _handle_event will pick up our fake class.
    """

    def __init__(self, *, success: bool = True, response_code: int | None = 200,
                 error: str | None = None, raise_exc: Exception | None = None):
        self._success = success
        self._response_code = response_code
        self._error = error
        self._raise_exc = raise_exc
        self.calls: list[tuple[dict, dict]] = []

    def send(self, payload: dict, config: dict) -> SendResult:
        self.calls.append((payload, config))
        if self._raise_exc is not None:
            raise self._raise_exc
        return SendResult(
            success=self._success,
            response_code=self._response_code,
            error=self._error,
        )


def _patch_senders(monkeypatch, *, slack=None, webhook=None, email=None):
    """Replace each sender class with a factory that returns the supplied fake.

    _handle_event does ``SlackSender()`` so we need a no-arg callable; the
    fakes are constructed once per test and shared via closure so the test can
    inspect call history after dispatch.
    """
    if slack is not None:
        import src.notifications.senders.slack as _slack_mod
        monkeypatch.setattr(_slack_mod, "SlackSender", lambda: slack)
    if webhook is not None:
        import src.notifications.senders.webhook as _webhook_mod
        monkeypatch.setattr(_webhook_mod, "GenericWebhookSender", lambda: webhook)
    if email is not None:
        import src.notifications.senders.email as _email_mod
        monkeypatch.setattr(_email_mod, "EmailSender", lambda: email)




class _RecordingPublisher:
    """Captures every event handed to publish() so tests can assert outcomes."""

    def __init__(self) -> None:
        self.published: list[Any] = []

    def publish(self, event: Any) -> None:
        self.published.append(event)


@pytest.fixture
def recording_publisher(monkeypatch):
    pub = _RecordingPublisher()
    # _handle_event imports get_event_publisher from src.shared.event_publisher
    # via deferred import — patch the symbol so the deferred lookup resolves
    # to our recorder.
    import src.shared.event_publisher as _pub_mod
    monkeypatch.setattr(_pub_mod, "get_event_publisher", lambda: pub)
    return pub




@pytest_asyncio.fixture
async def notif_cleanup(db_session):
    """Track destination / rule ids to delete at teardown.

    Deliveries cascade from destinations via FK, but the cleanup is explicit
    to keep teardown deterministic when assertions read deliveries.
    """
    destination_ids: list[int] = []
    rule_ids: list[str] = []
    yield destination_ids, rule_ids

    if rule_ids:
        await db_session.execute(
            sa_delete(NotificationRule).where(NotificationRule.id.in_(rule_ids))
        )
    if destination_ids:
        await db_session.execute(
            sa_delete(NotificationDelivery).where(
                NotificationDelivery.destination_id.in_(destination_ids)
            )
        )
        await db_session.execute(
            sa_delete(NotificationDestination).where(
                NotificationDestination.id.in_(destination_ids)
            )
        )
    await db_session.commit()




async def _create_slack_destination(
    db_session, destination_ids: list[int],
    *, name_prefix: str = "slack", event_filter: dict | None = None,
    enabled: bool = True,
) -> int:
    from src.notifications.destination import create_destination
    name = f"{name_prefix}-{uuid4().hex[:8]}"
    out = create_destination(
        destination_type="slack",
        name=name,
        config={"webhook_url": "https://hooks.example.test/x"},
        enabled=enabled,
        event_filter=event_filter,
    )
    destination_ids.append(out["id"])
    return out["id"]


async def _create_webhook_destination(
    db_session, destination_ids: list[int],
    *, name_prefix: str = "webhook",
) -> int:
    from src.notifications.destination import create_destination
    name = f"{name_prefix}-{uuid4().hex[:8]}"
    out = create_destination(
        destination_type="webhook",
        name=name,
        config={"url": "https://example.test/hook"},
    )
    destination_ids.append(out["id"])
    return out["id"]


async def _create_rule(
    db_session, rule_ids: list[str],
    *, channel_id: int, conditions: dict, priority: int = 100,
    enabled: bool = True, name_prefix: str = "rule",
) -> str:
    from src.notifications.rules_model import create_rule
    out = create_rule(
        name=f"{name_prefix}-{uuid4().hex[:8]}",
        channel_id=channel_id,
        conditions=conditions,
        priority=priority,
        enabled=enabled,
    )
    rule_ids.append(out["id"])
    return out["id"]


def _make_finding_event(severity: str = "critical", event_id: str | None = None) -> Event:
    # Envelope shape as published by EventPublisher: the finding fields live
    # under "payload"; event_id / org_id sit on the envelope alongside it.
    return Event(
        event_type="finding.created",
        data={
            "event_id": event_id or f"ev-{uuid4().hex[:8]}",
            "org_id": "acme-org",
            # Mirror the real emit_finding_created payload: it carries
            # scanner_type (NOT "scanner") and no repo_id. Using the wrong keys
            # here previously hid the scanner-condition routing bug.
            "payload": {
                "finding_id": f"f-{uuid4().hex[:8]}",
                "severity": severity,
                "scanner_type": "trivy",
            },
        },
    )




@pytest.mark.asyncio
async def test_handle_event_unsubscribed_type_is_noop(
    db_session, notif_cleanup, recording_publisher, monkeypatch,
):
    # _on_event guards against unsubscribed types — bus topics outside the
    # SUBSCRIBED_EVENT_TYPES set must NOT trigger any senders.
    destination_ids, _ = notif_cleanup
    await _create_slack_destination(db_session, destination_ids)
    await db_session.commit()

    slack = _FakeSender(success=True)
    _patch_senders(monkeypatch, slack=slack)

    router = NotificationEventRouter()
    event = Event(event_type="something.unrelated", data={"event_id": "ev-1"})
    router._on_event(event)

    assert slack.calls == []
    assert recording_publisher.published == []


@pytest.mark.asyncio
async def test_handle_event_dispatches_to_matching_slack_destination(
    db_session, notif_cleanup, recording_publisher, monkeypatch,
):
    # Happy path: no rules → legacy event_filter fanout (no filter = match all).
    # The slack sender's send() must be invoked with the formatted Slack
    # payload, and a delivered row + dispatched event must be recorded.
    destination_ids, _ = notif_cleanup
    dest_id = await _create_slack_destination(db_session, destination_ids)
    await db_session.commit()

    slack = _FakeSender(success=True, response_code=200)
    _patch_senders(monkeypatch, slack=slack)

    event = _make_finding_event(severity="high")
    router = NotificationEventRouter()
    router._handle_event(event)

    # Sender called exactly once, with the Slack-formatted payload + config.
    assert len(slack.calls) == 1
    payload, config = slack.calls[0]
    assert "blocks" in payload and "text" in payload
    assert read_config_secret(config["webhook_url"]) == "https://hooks.example.test/x"

    # Delivery row recorded as 'delivered'.
    rows = (await db_session.execute(
        select(NotificationDelivery).where(
            NotificationDelivery.destination_id == dest_id,
            NotificationDelivery.event_id == event.data["event_id"],
        )
    )).scalars().all()
    assert len(rows) == 1
    assert rows[0].status == "delivered"
    assert rows[0].response_code == 200

    # NotificationDispatchedEvent emitted.
    assert len(recording_publisher.published) == 1
    emitted = recording_publisher.published[0]
    assert emitted.event_type == "notification.dispatched"
    assert emitted.payload["destination_id"] == dest_id
    assert emitted.payload["destination_type"] == "slack"


@pytest.mark.asyncio
async def test_handle_event_sender_failure_parks_retry_and_emits_failed_event(
    db_session, notif_cleanup, recording_publisher, monkeypatch,
):
    # When a sender raises, the router must:
    #   - Catch the exception (not bubble out)
    #   - Park the delivery for retry (status='retry', attempts=1, backoff set,
    #     payload stored) with the error message truncated to <=500
    #   - Still emit NotificationFailedEvent (not Dispatched) for this attempt
    from datetime import datetime, timezone

    destination_ids, _ = notif_cleanup
    dest_id = await _create_slack_destination(db_session, destination_ids)
    await db_session.commit()

    slack = _FakeSender(raise_exc=RuntimeError("connection refused " + "x" * 1000))
    _patch_senders(monkeypatch, slack=slack)

    event = _make_finding_event()
    router = NotificationEventRouter()
    router._handle_event(event)

    rows = (await db_session.execute(
        select(NotificationDelivery).where(
            NotificationDelivery.destination_id == dest_id,
            NotificationDelivery.event_id == event.data["event_id"],
        )
    )).scalars().all()
    assert len(rows) == 1
    assert rows[0].status == "retry"
    assert rows[0].attempts == 1
    assert rows[0].next_attempt_at is not None
    assert rows[0].next_attempt_at > datetime.now(timezone.utc)
    assert rows[0].payload is not None
    assert rows[0].error is not None
    assert rows[0].error.startswith("connection refused")
    assert len(rows[0].error) <= 500

    assert len(recording_publisher.published) == 1
    emitted = recording_publisher.published[0]
    assert emitted.event_type == "notification.failed"
    assert emitted.payload["destination_id"] == dest_id


@pytest.mark.asyncio
async def test_handle_event_sender_returns_failure_parks_retry_with_response_code(
    db_session, notif_cleanup, recording_publisher, monkeypatch,
):
    # SendResult(success=False) without an exception — the router must park the
    # delivery for retry while preserving the response_code and error string.
    destination_ids, _ = notif_cleanup
    dest_id = await _create_slack_destination(db_session, destination_ids)
    await db_session.commit()

    slack = _FakeSender(success=False, response_code=429, error="rate limited")
    _patch_senders(monkeypatch, slack=slack)

    event = _make_finding_event()
    router = NotificationEventRouter()
    router._handle_event(event)

    rows = (await db_session.execute(
        select(NotificationDelivery).where(
            NotificationDelivery.destination_id == dest_id,
            NotificationDelivery.event_id == event.data["event_id"],
        )
    )).scalars().all()
    assert len(rows) == 1
    assert rows[0].status == "retry"
    assert rows[0].attempts == 1
    assert rows[0].response_code == 429
    assert rows[0].error == "rate limited"


@pytest.mark.asyncio
async def test_handle_event_no_destinations_noop(
    db_session, notif_cleanup, recording_publisher, monkeypatch,
):
    # No enabled destinations means no work — and crucially no delivery rows
    # so we don't pollute the audit table with orphan rows.
    destination_ids, _ = notif_cleanup
    # Create a destination but disable it; legacy fanout must skip it.
    await _create_slack_destination(db_session, destination_ids, enabled=False)
    await db_session.commit()

    slack = _FakeSender(success=True)
    _patch_senders(monkeypatch, slack=slack)

    event = _make_finding_event()
    router = NotificationEventRouter()
    router._handle_event(event)

    assert slack.calls == []
    assert recording_publisher.published == []


@pytest.mark.asyncio
async def test_handle_event_multiple_destinations_each_sender_called_independently(
    db_session, notif_cleanup, recording_publisher, monkeypatch,
):
    # Two destinations, two different sender types. One fails, the other
    # succeeds — the failure must not block the success path.
    destination_ids, _ = notif_cleanup
    slack_id = await _create_slack_destination(db_session, destination_ids)
    webhook_id = await _create_webhook_destination(db_session, destination_ids)
    await db_session.commit()

    slack = _FakeSender(success=True, response_code=200)
    webhook = _FakeSender(raise_exc=ConnectionError("dns fail"))
    _patch_senders(monkeypatch, slack=slack, webhook=webhook)

    event = _make_finding_event()
    router = NotificationEventRouter()
    router._handle_event(event)

    # Both senders called exactly once.
    assert len(slack.calls) == 1
    assert len(webhook.calls) == 1

    # Slack delivery recorded as delivered.
    slack_rows = (await db_session.execute(
        select(NotificationDelivery).where(
            NotificationDelivery.destination_id == slack_id,
            NotificationDelivery.event_id == event.data["event_id"],
        )
    )).scalars().all()
    assert len(slack_rows) == 1
    assert slack_rows[0].status == "delivered"

    # Webhook delivery parked for retry (a failed first attempt is no longer
    # dropped — it enters the retry queue).
    webhook_rows = (await db_session.execute(
        select(NotificationDelivery).where(
            NotificationDelivery.destination_id == webhook_id,
            NotificationDelivery.event_id == event.data["event_id"],
        )
    )).scalars().all()
    assert len(webhook_rows) == 1
    assert webhook_rows[0].status == "retry"

    # Two outcome events — one dispatched, one failed.
    types = sorted(e.event_type for e in recording_publisher.published)
    assert types == ["notification.dispatched", "notification.failed"]


@pytest.mark.asyncio
async def test_handle_event_event_filter_blocks_destination_with_min_severity(
    db_session, notif_cleanup, recording_publisher, monkeypatch,
):
    # Legacy fanout path: when no rules exist, each destination's own
    # event_filter is used to gate delivery. A "low" event must NOT reach a
    # destination that requires min_severity=high.
    destination_ids, _ = notif_cleanup
    await _create_slack_destination(
        db_session, destination_ids,
        event_filter={"min_severity": "high"},
    )
    await db_session.commit()

    slack = _FakeSender(success=True)
    _patch_senders(monkeypatch, slack=slack)

    event = _make_finding_event(severity="low")
    router = NotificationEventRouter()
    router._handle_event(event)

    assert slack.calls == []
    assert recording_publisher.published == []




@pytest.mark.asyncio
async def test_handle_event_rules_path_claims_destination_skipping_others(
    db_session, notif_cleanup, recording_publisher, monkeypatch,
):
    # When ANY active rule matches, only the rule's claimed channel receives
    # the event — other enabled destinations are skipped. This locks the
    # rules-vs-event-filter precedence: rules win.
    destination_ids, rule_ids = notif_cleanup
    target_id = await _create_slack_destination(db_session, destination_ids, name_prefix="target")
    await _create_webhook_destination(db_session, destination_ids, name_prefix="other")
    await db_session.commit()

    await _create_rule(
        db_session, rule_ids,
        channel_id=target_id,
        conditions={"field": "severity", "op": "eq", "value": "critical"},
        priority=1,
    )
    await db_session.commit()

    slack = _FakeSender(success=True, response_code=200)
    webhook = _FakeSender(success=True, response_code=200)
    _patch_senders(monkeypatch, slack=slack, webhook=webhook)

    event = _make_finding_event(severity="critical")
    router = NotificationEventRouter()
    router._handle_event(event)

    assert len(slack.calls) == 1
    assert webhook.calls == []

    # Only one delivery row, for the claimed target.
    rows = (await db_session.execute(
        select(NotificationDelivery).where(
            NotificationDelivery.event_id == event.data["event_id"],
        )
    )).scalars().all()
    assert {r.destination_id for r in rows} == {target_id}


@pytest.mark.asyncio
async def test_bug1_critical_event_passes_min_severity_filter_via_envelope_payload(
    db_session, notif_cleanup, recording_publisher, monkeypatch,
):
    # Bug 1: the router must unwrap event.data["payload"] to read the real
    # severity. A CRITICAL finding on a destination gated at min_severity=high
    # must be delivered. Before the fix, severity read off the envelope defaulted
    # to "info" and the min_severity gate silently dropped every finding.
    destination_ids, _ = notif_cleanup
    dest_id = await _create_slack_destination(
        db_session, destination_ids,
        event_filter={"min_severity": "high"},
    )
    await db_session.commit()

    slack = _FakeSender(success=True, response_code=200)
    _patch_senders(monkeypatch, slack=slack)

    event = _make_finding_event(severity="critical")
    router = NotificationEventRouter()
    router._handle_event(event)

    assert len(slack.calls) == 1
    rows = (await db_session.execute(
        select(NotificationDelivery).where(
            NotificationDelivery.destination_id == dest_id,
            NotificationDelivery.event_id == event.data["event_id"],
        )
    )).scalars().all()
    assert len(rows) == 1
    assert rows[0].status == "delivered"


@pytest.mark.asyncio
async def test_bug1_severity_rule_matches_and_claims_only_target(
    db_session, notif_cleanup, recording_publisher, monkeypatch,
):
    # Bug 1: a routing rule with condition severity == "critical" must match a
    # CRITICAL finding and claim ONLY its channel. Before the fix, severity read
    # as "info", the rule never matched, and routing collapsed to event-filter
    # fanout — delivering to the non-targeted destination too.
    destination_ids, rule_ids = notif_cleanup
    target_id = await _create_slack_destination(db_session, destination_ids, name_prefix="target")
    await _create_webhook_destination(db_session, destination_ids, name_prefix="other")
    await db_session.commit()

    await _create_rule(
        db_session, rule_ids,
        channel_id=target_id,
        conditions={"field": "severity", "op": "eq", "value": "critical"},
        priority=1,
    )
    await db_session.commit()

    slack = _FakeSender(success=True, response_code=200)
    webhook = _FakeSender(success=True, response_code=200)
    _patch_senders(monkeypatch, slack=slack, webhook=webhook)

    event = _make_finding_event(severity="critical")
    router = NotificationEventRouter()
    router._handle_event(event)

    assert len(slack.calls) == 1
    assert webhook.calls == []
    rows = (await db_session.execute(
        select(NotificationDelivery).where(
            NotificationDelivery.event_id == event.data["event_id"],
        )
    )).scalars().all()
    assert {r.destination_id for r in rows} == {target_id}


@pytest.mark.asyncio
async def test_scanner_rule_matches_via_real_payload_scanner_type_key(
    db_session, notif_cleanup, recording_publisher, monkeypatch,
):
    # The real finding.created payload carries the scanner name under
    # "scanner_type"; a routing rule conditioned on "scanner" must still match.
    # Before the fix the router only read "scanner", so it fell back to the
    # event_type and scanner-conditioned rules never matched.
    destination_ids, rule_ids = notif_cleanup
    target_id = await _create_slack_destination(db_session, destination_ids, name_prefix="target")
    await _create_webhook_destination(db_session, destination_ids, name_prefix="other")
    await db_session.commit()

    await _create_rule(
        db_session, rule_ids,
        channel_id=target_id,
        conditions={"field": "scanner", "op": "eq", "value": "trivy"},
        priority=1,
    )
    await db_session.commit()

    slack = _FakeSender(success=True, response_code=200)
    webhook = _FakeSender(success=True, response_code=200)
    _patch_senders(monkeypatch, slack=slack, webhook=webhook)

    event = _make_finding_event(severity="high")
    router = NotificationEventRouter()
    router._handle_event(event)

    assert len(slack.calls) == 1
    assert webhook.calls == []
    rows = (await db_session.execute(
        select(NotificationDelivery).where(
            NotificationDelivery.event_id == event.data["event_id"],
        )
    )).scalars().all()
    assert {r.destination_id for r in rows} == {target_id}


@pytest.mark.asyncio
async def test_bug2_rule_selected_destination_bypasses_own_event_filter(
    db_session, notif_cleanup, recording_publisher, monkeypatch,
):
    # Bug 2: a destination chosen by an explicit routing rule must be delivered
    # to even when its OWN event_filter would exclude the event — the rule has
    # already decided routing. Here the rule (severity == critical) claims a
    # destination whose event_filter demands min_severity=critical too, but the
    # point is the in-loop re-filter must not run for rule-selected dests.
    destination_ids, rule_ids = notif_cleanup
    # event_filter that would drop anything below critical; the rule condition is
    # what actually admits this event, and the loop must not re-apply the filter.
    dest_id = await _create_slack_destination(
        db_session, destination_ids,
        event_filter={"min_severity": "critical", "event_types": ["finding.severity_changed"]},
    )
    await db_session.commit()

    await _create_rule(
        db_session, rule_ids,
        channel_id=dest_id,
        conditions={"field": "severity", "op": "eq", "value": "critical"},
        priority=1,
    )
    await db_session.commit()

    slack = _FakeSender(success=True, response_code=200)
    _patch_senders(monkeypatch, slack=slack)

    # event_type finding.created is NOT in the dest's event_filter.event_types,
    # so the dest's own filter would exclude it — but the rule selected it.
    event = _make_finding_event(severity="critical")
    router = NotificationEventRouter()
    router._handle_event(event)

    assert len(slack.calls) == 1
    rows = (await db_session.execute(
        select(NotificationDelivery).where(
            NotificationDelivery.destination_id == dest_id,
            NotificationDelivery.event_id == event.data["event_id"],
        )
    )).scalars().all()
    assert len(rows) == 1
    assert rows[0].status == "delivered"


@pytest.mark.asyncio
async def test_handle_event_rules_exist_but_none_match_falls_back_to_event_filter(
    db_session, notif_cleanup, recording_publisher, monkeypatch,
):
    # Rules-vs-event-filter precedence (no-match branch): rules exist but none
    # match the event → fall back to legacy event_filter fanout. Both
    # destinations should receive the event (no event_filter on either).
    destination_ids, rule_ids = notif_cleanup
    slack_id = await _create_slack_destination(db_session, destination_ids)
    webhook_id = await _create_webhook_destination(db_session, destination_ids)
    await db_session.commit()

    # Rule only matches severity=critical; we'll send a "low" event so it doesn't fire.
    await _create_rule(
        db_session, rule_ids,
        channel_id=slack_id,
        conditions={"field": "severity", "op": "eq", "value": "critical"},
        priority=1,
    )
    await db_session.commit()

    slack = _FakeSender(success=True)
    webhook = _FakeSender(success=True)
    _patch_senders(monkeypatch, slack=slack, webhook=webhook)

    event = _make_finding_event(severity="low")
    router = NotificationEventRouter()
    router._handle_event(event)

    # Fallback fanout: both destinations get the event.
    assert len(slack.calls) == 1
    assert len(webhook.calls) == 1

    rows = (await db_session.execute(
        select(NotificationDelivery).where(
            NotificationDelivery.event_id == event.data["event_id"],
        )
    )).scalars().all()
    assert {r.destination_id for r in rows} == {slack_id, webhook_id}
