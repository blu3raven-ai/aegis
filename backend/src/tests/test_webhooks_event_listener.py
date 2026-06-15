"""Unit tests for the webhook -> CI-scan dispatcher.

These tests stand the listener up against a mocked ``submit_ci_scan`` and a
mocked DB session so the EventBus -> resolution -> dispatch chain is
exercised without spinning up runner jobs or hitting Postgres.
"""
from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest

from src.shared.event_bus import Event as SseEvent, EventBus
from src.webhooks import event_listener as listener_mod
from src.webhooks.event_listener import WebhookScanDispatcher


_FLAG = "AEGIS_WEBHOOK_DISPATCH_ENABLED"


@dataclass
class _FakeAsset:
    id: str
    external_ref: str
    archived: bool = False


def _fake_session_yielding(asset: _FakeAsset | None):
    """Return a get_session ctx-manager that yields a session whose
    ``execute`` returns the given asset (or None)."""

    class _ScalarResult:
        def __init__(self, value: Any) -> None:
            self._value = value

        def scalar_one_or_none(self) -> Any:
            return self._value

    class _Session:
        async def execute(self, _stmt: Any) -> _ScalarResult:
            return _ScalarResult(asset)

    @asynccontextmanager
    async def _ctx():
        yield _Session()

    return _ctx


def _push_event(repo_id: str = "acme-org/repo", *, source_component: str = "integrations.github") -> SseEvent:
    return SseEvent(
        event_type="code.push",
        data={
            "event_id": "evt-1",
            "org_id": "acme-org",
            "source_component": source_component,
            "payload": {
                "repo_id": repo_id,
                "ref": "refs/heads/main",
                "before_sha": "0" * 40,
                "after_sha": "a" * 40,
                "commits": [],
            },
        },
    )


def _pr_opened_event(repo_id: str = "acme-org/repo") -> SseEvent:
    return SseEvent(
        event_type="code.pr_opened",
        data={
            "event_id": "evt-2",
            "org_id": "acme-org",
            "source_component": "integrations.github",
            "payload": {
                "repo_id": repo_id,
                "pr_number": 42,
                "base_sha": "b" * 40,
                "head_sha": "c" * 40,
                "author": "alice",
                "title": "feat: x",
            },
        },
    )


# ── start()/stop() & feature flag ─────────────────────────────────────────────

def test_start_is_noop_when_flag_unset(monkeypatch):
    monkeypatch.delenv(_FLAG, raising=False)
    bus = EventBus()
    d = WebhookScanDispatcher(event_bus=bus)
    d.start()
    assert d._listener_token is None  # noqa: SLF001 — assert internal token
    assert len(bus._listeners) == 0  # noqa: SLF001 — direct introspection


def test_start_registers_when_flag_true(monkeypatch):
    monkeypatch.setenv(_FLAG, "true")

    async def _run():
        bus = EventBus()
        bus.set_loop(asyncio.get_running_loop())
        d = WebhookScanDispatcher(event_bus=bus)
        d.start()
        assert d._listener_token is not None  # noqa: SLF001
        assert len(bus._listeners) == 1  # noqa: SLF001
        d.stop()
        assert d._listener_token is None  # noqa: SLF001
        assert len(bus._listeners) == 0  # noqa: SLF001

    asyncio.run(_run())


def test_start_refuses_when_bus_has_no_loop(monkeypatch, caplog):
    """If main.py forgets to call set_loop() before starting the dispatcher,
    start() must refuse rather than silently degrade to inline asyncio.run."""
    monkeypatch.setenv(_FLAG, "true")
    bus = EventBus()  # no set_loop()
    d = WebhookScanDispatcher(event_bus=bus)
    with caplog.at_level("ERROR", logger="src.webhooks.event_listener"):
        d.start()
    assert d._listener_token is None  # noqa: SLF001
    assert len(bus._listeners) == 0  # noqa: SLF001
    assert any("no captured loop" in r.message for r in caplog.records)


def test_start_is_idempotent(monkeypatch):
    monkeypatch.setenv(_FLAG, "true")

    async def _run():
        bus = EventBus()
        bus.set_loop(asyncio.get_running_loop())
        d = WebhookScanDispatcher(event_bus=bus)
        d.start()
        first_token = d._listener_token  # noqa: SLF001
        d.start()
        assert d._listener_token == first_token  # noqa: SLF001
        assert len(bus._listeners) == 1  # noqa: SLF001
        d.stop()

    asyncio.run(_run())


def test_stop_is_idempotent(monkeypatch):
    monkeypatch.setenv(_FLAG, "true")

    async def _run():
        bus = EventBus()
        bus.set_loop(asyncio.get_running_loop())
        d = WebhookScanDispatcher(event_bus=bus)
        d.start()
        d.stop()
        d.stop()  # no raise

    asyncio.run(_run())


def test_on_event_drops_when_loop_not_set(caplog):
    """If something hand-registers the listener without going through start(),
    the dispatcher must drop the event loudly rather than asyncio.run inline."""
    bus = EventBus()
    d = WebhookScanDispatcher(event_bus=bus)
    # Intentionally bypass start(): no loop captured.
    assert d._loop is None  # noqa: SLF001
    with caplog.at_level("ERROR", logger="src.webhooks.event_listener"), \
         patch.object(listener_mod, "submit_ci_scan", new=AsyncMock()) as mock_submit:
        d._on_event(_push_event())  # noqa: SLF001
    mock_submit.assert_not_called()
    assert any("no loop captured" in r.message for r in caplog.records)


# ── dispatch happy paths ──────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_dispatch_push_submits_scan_with_branch():
    asset = _FakeAsset(id="asset-1", external_ref="github:acme-org/repo")
    bus = EventBus()
    bus.set_loop(asyncio.get_running_loop())
    d = WebhookScanDispatcher(event_bus=bus)

    with (
        patch.object(listener_mod, "get_session", _fake_session_yielding(asset)),
        patch.object(listener_mod, "find_inflight_scan", new=AsyncMock(return_value=None)),
        patch.object(listener_mod, "submit_ci_scan", new=AsyncMock()) as mock_submit,
    ):
        await d._dispatch(_push_event())  # noqa: SLF001 — direct dispatch

    mock_submit.assert_awaited_once()
    kwargs = mock_submit.call_args.kwargs
    assert kwargs["source_id"] == "asset-1"
    assert kwargs["commit_sha"] == "a" * 40
    assert kwargs["branch"] == "main"
    assert kwargs["pr_number"] is None
    assert kwargs["triggered_by"] == "webhook"
    assert kwargs["org"] == "acme-org"
    meta = kwargs["trigger_metadata"]
    assert meta["provider"] == "github"
    assert meta["event_id"] == "evt-1"
    assert meta["event_type"] == "code.push"
    assert meta["ref"] == "refs/heads/main"


@pytest.mark.asyncio
async def test_dispatch_pr_opened_submits_with_head_sha_and_pr_number():
    asset = _FakeAsset(id="asset-2", external_ref="github:acme-org/repo")
    bus = EventBus()
    d = WebhookScanDispatcher(event_bus=bus)

    with (
        patch.object(listener_mod, "get_session", _fake_session_yielding(asset)),
        patch.object(listener_mod, "find_inflight_scan", new=AsyncMock(return_value=None)),
        patch.object(listener_mod, "submit_ci_scan", new=AsyncMock()) as mock_submit,
    ):
        await d._dispatch(_pr_opened_event())  # noqa: SLF001

    kwargs = mock_submit.call_args.kwargs
    assert kwargs["source_id"] == "asset-2"
    assert kwargs["commit_sha"] == "c" * 40
    assert kwargs["pr_number"] == 42
    assert kwargs["branch"] is None
    assert kwargs["triggered_by"] == "webhook"


@pytest.mark.asyncio
async def test_dispatch_resolves_gitlab_nested_group():
    """Lock the rpartition split for GitLab. A 4-segment path is used so that
    partition and rpartition diverge on the (owner, name) tuple passed to
    repo_ref — both produce the same final ``gitlab:acme-org/group/sub/repo``
    string, but only rpartition yields the semantically correct owner=
    ``acme-org/group/sub`` and name=``repo``. The test fails if someone
    regresses the listener to ``partition`` for GitLab."""
    asset = _FakeAsset(id="asset-3", external_ref="gitlab:acme-org/group/sub/repo")
    bus = EventBus()
    d = WebhookScanDispatcher(event_bus=bus)

    event = _push_event(repo_id="acme-org/group/sub/repo", source_component="integrations.gitlab")

    repo_ref_calls: list[tuple[str, str, str]] = []

    def _capturing_repo_ref(source_type: str, owner: str, name: str) -> str:
        repo_ref_calls.append((source_type, owner, name))
        return f"{source_type}:{owner}/{name}"

    with (
        patch.object(listener_mod, "get_session", _fake_session_yielding(asset)),
        patch.object(listener_mod, "repo_ref", side_effect=_capturing_repo_ref),
        patch.object(listener_mod, "find_inflight_scan", new=AsyncMock(return_value=None)),
        patch.object(listener_mod, "submit_ci_scan", new=AsyncMock()) as mock_submit,
    ):
        await d._dispatch(event)  # noqa: SLF001

    mock_submit.assert_awaited_once()
    assert mock_submit.call_args.kwargs["source_id"] == "asset-3"
    # The rpartition branch must produce owner=acme-org/group/sub, name=repo.
    # If someone regresses to partition() for GitLab, owner would be "acme-org"
    # and name would be "group/sub/repo" — this assertion locks the correct split.
    assert repo_ref_calls == [("gitlab", "acme-org/group/sub", "repo")]


@pytest.mark.asyncio
async def test_dispatch_calls_find_inflight_with_empty_org():
    """The dispatcher passes org="" to find_inflight_scan to mirror the CI
    router. The find_inflight_scan helper currently ignores the arg; keeping
    one call shape means the eventual cross-org follow-up touches one site."""
    asset = _FakeAsset(id="asset-4", external_ref="github:acme-org/repo")
    bus = EventBus()
    d = WebhookScanDispatcher(event_bus=bus)

    mock_find = AsyncMock(return_value=None)
    with (
        patch.object(listener_mod, "get_session", _fake_session_yielding(asset)),
        patch.object(listener_mod, "find_inflight_scan", new=mock_find),
        patch.object(listener_mod, "submit_ci_scan", new=AsyncMock()),
    ):
        await d._dispatch(_push_event())  # noqa: SLF001

    mock_find.assert_awaited_once()
    assert mock_find.call_args.kwargs["org"] == ""


@pytest.mark.asyncio
async def test_dispatch_emits_audit_log_on_success():
    """A webhook-triggered scan must be visible in audit_log alongside the
    CI-router path. Actor is shaped as ``webhook:<provider>`` and metadata
    mirrors the CI-router shape, augmented with provider/event_id."""
    from src.audit_log.recorder import ActorInfo, RequestContext

    asset = _FakeAsset(id="asset-audit", external_ref="github:acme-org/repo")
    bus = EventBus()
    d = WebhookScanDispatcher(event_bus=bus)

    fake_submission = type("S", (), {"scan_id": "scan-abc"})()

    recorded: dict = {}

    class _CapturingRecorder:
        def record(self, **kwargs):
            recorded.update(kwargs)

    with (
        patch.object(listener_mod, "get_session", _fake_session_yielding(asset)),
        patch.object(listener_mod, "find_inflight_scan", new=AsyncMock(return_value=None)),
        patch.object(listener_mod, "submit_ci_scan", new=AsyncMock(return_value=fake_submission)),
        patch.object(listener_mod, "get_recorder", return_value=_CapturingRecorder()),
    ):
        await d._dispatch(_push_event())  # noqa: SLF001

    assert recorded["action"] == "scan.triggered"
    assert recorded["resource_type"] == "scan_run"
    assert recorded["resource_id"] == "scan-abc"
    assert isinstance(recorded["actor"], ActorInfo)
    assert recorded["actor"].user_id == "webhook:github"
    meta = recorded["metadata"]
    assert meta["triggered_by"] == "webhook"
    assert meta["provider"] == "github"
    assert meta["event_id"] == "evt-1"
    assert meta["event_type"] == "code.push"
    assert meta["source_id"] == "asset-audit"
    assert meta["commit_sha"] == "a" * 40
    assert meta["pr_number"] is None
    assert meta["ref"] == "refs/heads/main"
    assert isinstance(recorded["request"], RequestContext)
    assert recorded["request"].path == "/integrations/github/webhook"


@pytest.mark.asyncio
async def test_dispatch_swallows_audit_recorder_failure(caplog):
    """A failing audit write must never break the scan submission path."""
    asset = _FakeAsset(id="asset-audit-fail", external_ref="github:acme-org/repo")
    bus = EventBus()
    d = WebhookScanDispatcher(event_bus=bus)

    fake_submission = type("S", (), {"scan_id": "scan-xyz"})()

    class _FailingRecorder:
        def record(self, **_kwargs):
            raise RuntimeError("audit DB unreachable")

    with (
        patch.object(listener_mod, "get_session", _fake_session_yielding(asset)),
        patch.object(listener_mod, "find_inflight_scan", new=AsyncMock(return_value=None)),
        patch.object(listener_mod, "submit_ci_scan", new=AsyncMock(return_value=fake_submission)) as mock_submit,
        patch.object(listener_mod, "get_recorder", return_value=_FailingRecorder()),
        caplog.at_level("ERROR", logger="src.webhooks.event_listener"),
    ):
        await d._dispatch(_push_event())  # noqa: SLF001

    mock_submit.assert_awaited_once()
    assert any("audit_log" in r.message for r in caplog.records)


# ── PR scan-queue cleanup parity ─────────────────────────────────────────────

@pytest.mark.asyncio
async def test_dispatch_pr_opened_cancels_older_queued():
    """Mirror trigger_router.py:98 — a PR-triggered webhook scan must cancel
    older queued scans for the same (asset, pr_number) so push spam on a PR
    branch doesn't pile up behind the in-flight scan."""
    asset = _FakeAsset(id="asset-pr-cancel", external_ref="github:acme-org/repo")
    bus = EventBus()
    d = WebhookScanDispatcher(event_bus=bus)

    fake_submission = type("S", (), {"scan_id": "scan-new"})()
    mock_cancel = AsyncMock(return_value=[])

    with (
        patch.object(listener_mod, "get_session", _fake_session_yielding(asset)),
        patch.object(listener_mod, "find_inflight_scan", new=AsyncMock(return_value=None)),
        patch.object(listener_mod, "submit_ci_scan", new=AsyncMock(return_value=fake_submission)),
        patch.object(listener_mod, "cancel_older_queued_for_pr", new=mock_cancel),
    ):
        await d._dispatch(_pr_opened_event())  # noqa: SLF001

    mock_cancel.assert_awaited_once()
    kwargs = mock_cancel.call_args.kwargs
    assert kwargs["org"] == ""
    assert kwargs["source_id"] == "asset-pr-cancel"
    assert kwargs["pr_number"] == 42
    assert kwargs["keep_scan_id"] == "scan-new"


@pytest.mark.asyncio
async def test_dispatch_push_does_not_call_cancel_older():
    """code.push has no pr_number; cancel_older_queued_for_pr is PR-only."""
    asset = _FakeAsset(id="asset-push", external_ref="github:acme-org/repo")
    bus = EventBus()
    d = WebhookScanDispatcher(event_bus=bus)

    fake_submission = type("S", (), {"scan_id": "scan-push"})()
    mock_cancel = AsyncMock()

    with (
        patch.object(listener_mod, "get_session", _fake_session_yielding(asset)),
        patch.object(listener_mod, "find_inflight_scan", new=AsyncMock(return_value=None)),
        patch.object(listener_mod, "submit_ci_scan", new=AsyncMock(return_value=fake_submission)),
        patch.object(listener_mod, "cancel_older_queued_for_pr", new=mock_cancel),
    ):
        await d._dispatch(_push_event())  # noqa: SLF001

    mock_cancel.assert_not_awaited()


@pytest.mark.asyncio
async def test_dispatch_swallows_cancel_older_failure(caplog):
    """A failing cancel must not break the audit emit. The CI router lets the
    exception bubble to the HTTP layer; the listener has no caller to surface
    it to, so it logs and continues."""
    from src.audit_log.recorder import ActorInfo

    asset = _FakeAsset(id="asset-cancel-fail", external_ref="github:acme-org/repo")
    bus = EventBus()
    d = WebhookScanDispatcher(event_bus=bus)

    fake_submission = type("S", (), {"scan_id": "scan-cancel-fail"})()
    failing_cancel = AsyncMock(side_effect=RuntimeError("cancel DB unreachable"))

    recorded: dict = {}

    class _CapturingRecorder:
        def record(self, **kwargs):
            recorded.update(kwargs)

    with (
        patch.object(listener_mod, "get_session", _fake_session_yielding(asset)),
        patch.object(listener_mod, "find_inflight_scan", new=AsyncMock(return_value=None)),
        patch.object(listener_mod, "submit_ci_scan", new=AsyncMock(return_value=fake_submission)),
        patch.object(listener_mod, "cancel_older_queued_for_pr", new=failing_cancel),
        patch.object(listener_mod, "get_recorder", return_value=_CapturingRecorder()),
        caplog.at_level("ERROR", logger="src.webhooks.event_listener"),
    ):
        await d._dispatch(_pr_opened_event())  # noqa: SLF001

    failing_cancel.assert_awaited_once()
    assert any("cancel_older_queued_for_pr failed" in r.message for r in caplog.records)
    # Audit log must still fire after the cancel failure.
    assert recorded["action"] == "scan.triggered"
    assert recorded["resource_id"] == "scan-cancel-fail"
    assert isinstance(recorded["actor"], ActorInfo)


# ── skip paths ────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_dispatch_skips_when_asset_missing(caplog):
    bus = EventBus()
    d = WebhookScanDispatcher(event_bus=bus)

    with (
        patch.object(listener_mod, "get_session", _fake_session_yielding(None)),
        patch.object(listener_mod, "find_inflight_scan", new=AsyncMock(return_value=None)),
        patch.object(listener_mod, "submit_ci_scan", new=AsyncMock()) as mock_submit,
        caplog.at_level("INFO", logger="src.webhooks.event_listener"),
    ):
        await d._dispatch(_push_event())  # noqa: SLF001

    mock_submit.assert_not_awaited()
    assert any("no asset registered" in r.message for r in caplog.records)


@pytest.mark.asyncio
async def test_dispatch_skips_when_inflight_scan_exists(caplog):
    asset = _FakeAsset(id="asset-5", external_ref="github:acme-org/repo")
    existing = type("R", (), {"id": "scan-existing"})()
    bus = EventBus()
    d = WebhookScanDispatcher(event_bus=bus)

    with (
        patch.object(listener_mod, "get_session", _fake_session_yielding(asset)),
        patch.object(listener_mod, "find_inflight_scan", new=AsyncMock(return_value=existing)),
        patch.object(listener_mod, "submit_ci_scan", new=AsyncMock()) as mock_submit,
        caplog.at_level("INFO", logger="src.webhooks.event_listener"),
    ):
        await d._dispatch(_push_event())  # noqa: SLF001

    mock_submit.assert_not_awaited()
    assert any("duplicate scan suppressed" in r.message for r in caplog.records)
    assert any("scan-existing" in r.message for r in caplog.records)


@pytest.mark.asyncio
async def test_dispatch_skips_when_asset_archived(caplog):
    asset = _FakeAsset(id="asset-6", external_ref="github:acme-org/repo", archived=True)
    bus = EventBus()
    d = WebhookScanDispatcher(event_bus=bus)

    with (
        patch.object(listener_mod, "get_session", _fake_session_yielding(asset)),
        patch.object(listener_mod, "find_inflight_scan", new=AsyncMock(return_value=None)),
        patch.object(listener_mod, "submit_ci_scan", new=AsyncMock()) as mock_submit,
        caplog.at_level("INFO", logger="src.webhooks.event_listener"),
    ):
        await d._dispatch(_push_event())  # noqa: SLF001

    mock_submit.assert_not_awaited()
    assert any("archived" in r.message for r in caplog.records)


@pytest.mark.asyncio
async def test_dispatch_skips_push_with_no_after_sha(caplog):
    asset = _FakeAsset(id="asset-7", external_ref="github:acme-org/repo")
    event = SseEvent(
        event_type="code.push",
        data={
            "event_id": "evt-x",
            "org_id": "acme-org",
            "source_component": "integrations.github",
            "payload": {"repo_id": "acme-org/repo", "ref": "refs/heads/main", "after_sha": None},
        },
    )
    bus = EventBus()
    d = WebhookScanDispatcher(event_bus=bus)

    with (
        patch.object(listener_mod, "get_session", _fake_session_yielding(asset)),
        patch.object(listener_mod, "find_inflight_scan", new=AsyncMock(return_value=None)),
        patch.object(listener_mod, "submit_ci_scan", new=AsyncMock()) as mock_submit,
        caplog.at_level("INFO", logger="src.webhooks.event_listener"),
    ):
        await d._dispatch(event)  # noqa: SLF001

    mock_submit.assert_not_awaited()


# ── irrelevant event types ────────────────────────────────────────────────────

def test_on_event_ignores_irrelevant_types(monkeypatch):
    monkeypatch.setenv(_FLAG, "true")
    bus = EventBus()
    d = WebhookScanDispatcher(event_bus=bus)
    # Bypass start() so the listener doesn't need a running loop; drive _on_event
    # directly. The dispatcher must not raise and must not invoke submit_ci_scan.
    with patch.object(listener_mod, "submit_ci_scan", new=AsyncMock()) as mock_submit:
        for et in ("finding.created", "code.image_push", "code.file_save", "code.manual_rescan"):
            d._on_event(SseEvent(event_type=et, data={"payload": {}}))  # noqa: SLF001
    mock_submit.assert_not_called()


# ── exception isolation ──────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_dispatch_swallows_submit_ci_scan_exception(caplog):
    asset = _FakeAsset(id="asset-8", external_ref="github:acme-org/repo")
    bus = EventBus()
    d = WebhookScanDispatcher(event_bus=bus)

    failing_submit = AsyncMock(side_effect=RuntimeError("boom"))

    with (
        patch.object(listener_mod, "get_session", _fake_session_yielding(asset)),
        patch.object(listener_mod, "find_inflight_scan", new=AsyncMock(return_value=None)),
        patch.object(listener_mod, "submit_ci_scan", new=failing_submit),
        caplog.at_level("ERROR", logger="src.webhooks.event_listener"),
    ):
        # _dispatch wraps _dispatch_unchecked in try/except; no exception should escape.
        await d._dispatch(_push_event())  # noqa: SLF001

    failing_submit.assert_awaited_once()
    assert any("dispatch failed" in r.message for r in caplog.records)


# ── async bridging via a real loop ───────────────────────────────────────────

def test_async_bridge_runs_dispatch_on_loop(monkeypatch):
    """When start() runs in an async context the dispatcher captures the loop
    and schedules dispatches via run_coroutine_threadsafe; we exercise the
    same path by driving _on_event with a captured loop."""
    monkeypatch.setenv(_FLAG, "true")
    asset = _FakeAsset(id="asset-9", external_ref="github:acme-org/repo")
    bus = EventBus()
    submitted: list[dict] = []

    async def fake_submit(**kwargs):
        submitted.append(kwargs)

    async def _main():
        bus.set_loop(asyncio.get_running_loop())
        d = WebhookScanDispatcher(event_bus=bus)
        d.start()
        with (
            patch.object(listener_mod, "get_session", _fake_session_yielding(asset)),
            patch.object(listener_mod, "find_inflight_scan", new=AsyncMock(return_value=None)),
            patch.object(listener_mod, "submit_ci_scan", side_effect=fake_submit),
        ):
            bus.publish(_push_event())
            # Yield so the scheduled coroutine actually runs.
            for _ in range(10):
                await asyncio.sleep(0.01)
                if submitted:
                    break
        d.stop()

    asyncio.run(_main())

    assert len(submitted) == 1
    assert submitted[0]["source_id"] == "asset-9"
