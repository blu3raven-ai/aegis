"""Unit tests for the audit-stream poster loop and delivery batching.

Covers cursor advancement, error handling, encrypted-token decryption,
target-type routing, backoff progression, and the poster_loop's
stop_event behavior. Uses mocked run_db so no real DB is touched —
delivery adapters are stubbed so no real network is hit.
"""
from __future__ import annotations

import asyncio
import json
import os
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

# Cryptography requires a real Fernet key; tests touch encrypt()/decrypt().
os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost:5432/test")
os.environ.setdefault("APP_SECRET", "0" * 64)
os.environ.setdefault("APP_SECRET", "FAjK_lhsKHqBJ4uYY3oRWAa7c1pTkbHIfk7gjhFCpx8=")

import pytest  # noqa: E402

from src.audit_stream import poster  # noqa: E402
from src.db.models import AuditEvent, AuditStreamConfig  # noqa: E402
from src.security.crypto import encrypt  # noqa: E402


@asynccontextmanager
async def _always_acquired(_key):
    yield True


@pytest.fixture(autouse=True)
def _stub_advisory_lock():
    """These tests mock run_db so no real DB is touched; bypass the HA gate."""
    with patch("src.audit_stream.poster.try_advisory_lock", new=_always_acquired):
        yield


def _event(id_: int) -> AuditEvent:
    evt = AuditEvent()
    evt.id = id_
    evt.action = "test.poster"
    evt.actor_user_id = "u-1"
    evt.actor_username = "alice"
    evt.actor_email = "alice@example.com"
    evt.resource_type = "user"
    evt.resource_id = str(id_)
    evt.metadata_json = {"n": id_}
    evt.created_at = datetime(2026, 1, 1, tzinfo=timezone.utc)
    return evt


def _cfg(
    *,
    enabled: bool = True,
    target_type: str | None = "webhook",
    endpoint_url: str | None = "https://hook.example.com/x",
    auth_token_enc: str | None = None,
    last_event_id: int = 0,
) -> AuditStreamConfig:
    cfg = AuditStreamConfig()
    cfg.id = 1
    cfg.enabled = enabled
    cfg.target_type = target_type
    cfg.endpoint_url = endpoint_url
    cfg.auth_token_enc = auth_token_enc
    cfg.last_event_id = last_event_id
    cfg.last_success_at = None
    cfg.last_error = None
    return cfg


def _drive_coro_in_isolated_loop(coro_fn, session) -> None:
    """Execute the write-side coroutine on a dedicated background thread.

    The outer `asyncio.run(poster.deliver_batch_once())` already owns a loop on
    this thread, so a sibling loop must run elsewhere. A throwaway thread
    mirrors how `run_db` itself runs in production (background thread + loop).
    """
    import threading

    error: list[BaseException] = []

    def _runner() -> None:
        loop = asyncio.new_event_loop()
        try:
            loop.run_until_complete(coro_fn(session))
        except BaseException as exc:  # noqa: BLE001 — surface to caller
            error.append(exc)
        finally:
            loop.close()

    t = threading.Thread(target=_runner)
    t.start()
    t.join()
    if error:
        raise error[0]


def _read_response(cfg: AuditStreamConfig, events: list[AuditEvent]) -> dict | None:
    """Mirror the snapshot dict the real _read() returns inside deliver_batch_once."""
    if not cfg.enabled or cfg.target_type is None or cfg.endpoint_url is None:
        return None
    from src.security.crypto import decrypt
    return {
        "target_type": cfg.target_type,
        "endpoint_url": cfg.endpoint_url,
        "token": decrypt(cfg.auth_token_enc) if cfg.auth_token_enc else None,
        "events": [poster._event_to_dict(e) for e in events],
        "last_id": events[-1].id if events else cfg.last_event_id,
    }




def test_deliver_batch_once_skipped_when_disabled():
    cfg = _cfg(enabled=False)

    def fake_run_db(coro_fn):
        return _read_response(cfg, [])

    with patch("src.audit_stream.poster.run_db", side_effect=fake_run_db):
        result = asyncio.run(poster.deliver_batch_once())
    assert result == {"delivered": 0, "skipped": True}


def test_deliver_batch_once_skipped_when_no_target_type():
    cfg = _cfg(target_type=None)

    def fake_run_db(coro_fn):
        return _read_response(cfg, [])

    with patch("src.audit_stream.poster.run_db", side_effect=fake_run_db):
        result = asyncio.run(poster.deliver_batch_once())
    assert result["skipped"] is True


def test_deliver_batch_once_skipped_when_no_endpoint_url():
    cfg = _cfg(endpoint_url=None)

    def fake_run_db(coro_fn):
        return _read_response(cfg, [])

    with patch("src.audit_stream.poster.run_db", side_effect=fake_run_db):
        result = asyncio.run(poster.deliver_batch_once())
    assert result["skipped"] is True


def test_deliver_batch_once_returns_zero_when_no_new_events():
    cfg = _cfg()

    def fake_run_db(coro_fn):
        return _read_response(cfg, [])

    with patch("src.audit_stream.poster.run_db", side_effect=fake_run_db):
        result = asyncio.run(poster.deliver_batch_once())
    assert result == {"delivered": 0, "skipped": False}




def test_deliver_batch_once_decrypts_token_before_send():
    cfg = _cfg(auth_token_enc=encrypt("secret-bearer-99"))
    events = [_event(1), _event(2)]

    calls = {"n": 0}

    def fake_run_db(coro_fn):
        calls["n"] += 1
        if calls["n"] == 1:
            return _read_response(cfg, events)
        return None  # write path is a no-op in unit tests

    captured = {}

    async def fake_webhook(url, token, payload, transport=None):
        captured["url"] = url
        captured["token"] = token
        captured["count"] = len(payload)
        return {"ok": True, "error": None}

    with patch("src.audit_stream.poster.run_db", side_effect=fake_run_db), \
         patch("src.audit_stream.poster.webhook_deliver", new=fake_webhook):
        result = asyncio.run(poster.deliver_batch_once())

    assert result["delivered"] == 2
    assert captured["token"] == "secret-bearer-99"
    assert captured["url"] == "https://hook.example.com/x"


def test_deliver_batch_once_routes_splunk_hec_target():
    cfg = _cfg(target_type="splunk_hec", endpoint_url="https://splunk.example.com:8088")
    events = [_event(1)]

    calls = {"n": 0}

    def fake_run_db(coro_fn):
        calls["n"] += 1
        if calls["n"] == 1:
            return _read_response(cfg, events)
        return None

    called = {"splunk": 0, "webhook": 0}

    async def fake_splunk(url, token, payload, transport=None):
        called["splunk"] += 1
        return {"ok": True, "error": None}

    async def fake_webhook(url, token, payload, transport=None):
        called["webhook"] += 1
        return {"ok": True, "error": None}

    with patch("src.audit_stream.poster.run_db", side_effect=fake_run_db), \
         patch("src.audit_stream.poster.splunk_hec_deliver", new=fake_splunk), \
         patch("src.audit_stream.poster.webhook_deliver", new=fake_webhook):
        result = asyncio.run(poster.deliver_batch_once())

    assert result["delivered"] == 1
    assert called["splunk"] == 1
    assert called["webhook"] == 0


def test_deliver_batch_once_routes_syslog_target():
    cfg = _cfg(target_type="syslog", endpoint_url="logs.example.com:514")
    events = [_event(1)]

    calls = {"n": 0}

    def fake_run_db(coro_fn):
        calls["n"] += 1
        if calls["n"] == 1:
            return _read_response(cfg, events)
        return None

    called = {"syslog": 0}

    async def fake_syslog(url, token, payload):
        called["syslog"] += 1
        return {"ok": True, "error": None}

    with patch("src.audit_stream.poster.run_db", side_effect=fake_run_db), \
         patch("src.audit_stream.poster.syslog_deliver", new=fake_syslog):
        result = asyncio.run(poster.deliver_batch_once())

    assert result["delivered"] == 1
    assert called["syslog"] == 1


def test_deliver_batch_once_unknown_target_type_returns_error():
    cfg = _cfg(target_type="wat-is-this")
    events = [_event(1)]

    calls = {"n": 0}

    def fake_run_db(coro_fn):
        calls["n"] += 1
        if calls["n"] == 1:
            return _read_response(cfg, events)
        return None

    with patch("src.audit_stream.poster.run_db", side_effect=fake_run_db):
        result = asyncio.run(poster.deliver_batch_once())

    assert result["delivered"] == 0
    assert result["error"] is not None
    assert "Unknown target_type" in result["error"]




def test_deliver_batch_once_failure_leaves_delivered_at_zero():
    cfg = _cfg()
    events = [_event(1), _event(2), _event(3)]

    calls = {"n": 0}

    def fake_run_db(coro_fn):
        calls["n"] += 1
        if calls["n"] == 1:
            return _read_response(cfg, events)
        return None

    async def fake_webhook(url, token, payload, transport=None):
        return {"ok": False, "error": "HTTP 502: bad gateway"}

    with patch("src.audit_stream.poster.run_db", side_effect=fake_run_db), \
         patch("src.audit_stream.poster.webhook_deliver", new=fake_webhook):
        result = asyncio.run(poster.deliver_batch_once())

    assert result["delivered"] == 0
    assert result["error"] == "HTTP 502: bad gateway"


def test_deliver_batch_once_failure_records_last_error_and_keeps_cursor():
    """On failure, write path must surface the error and NOT advance last_event_id."""
    cfg = _cfg(last_event_id=10)
    events = [_event(11), _event(12)]

    snap_returned = False
    write_cfg: AuditStreamConfig | None = None

    def fake_run_db(coro_fn):
        nonlocal snap_returned, write_cfg
        if not snap_returned:
            snap_returned = True
            return _read_response(cfg, events)
        # Simulate the write transaction by handing it the same row object
        # and capturing what fields the poster mutates.
        write_cfg = cfg
        # Drive the coroutine with a fake session that returns the cfg.
        session = MagicMock()
        execute_result = MagicMock()
        execute_result.scalar_one.return_value = cfg
        session.execute = AsyncMock(return_value=execute_result)
        _drive_coro_in_isolated_loop(coro_fn, session)
        return None

    async def fake_webhook(url, token, payload, transport=None):
        return {"ok": False, "error": "boom"}

    with patch("src.audit_stream.poster.run_db", side_effect=fake_run_db), \
         patch("src.audit_stream.poster.webhook_deliver", new=fake_webhook):
        result = asyncio.run(poster.deliver_batch_once())

    assert result["delivered"] == 0
    assert write_cfg is cfg
    assert cfg.last_event_id == 10  # cursor un-advanced
    assert cfg.last_error == "boom"


def test_deliver_batch_once_success_advances_cursor_and_clears_error():
    cfg = _cfg(last_event_id=5)
    cfg.last_error = "prior failure"
    events = [_event(6), _event(7), _event(8)]

    snap_returned = False

    def fake_run_db(coro_fn):
        nonlocal snap_returned
        if not snap_returned:
            snap_returned = True
            return _read_response(cfg, events)
        session = MagicMock()
        execute_result = MagicMock()
        execute_result.scalar_one.return_value = cfg
        session.execute = AsyncMock(return_value=execute_result)
        _drive_coro_in_isolated_loop(coro_fn, session)
        return None

    async def fake_webhook(url, token, payload, transport=None):
        return {"ok": True, "error": None}

    with patch("src.audit_stream.poster.run_db", side_effect=fake_run_db), \
         patch("src.audit_stream.poster.webhook_deliver", new=fake_webhook):
        result = asyncio.run(poster.deliver_batch_once())

    assert result["delivered"] == 3
    assert cfg.last_event_id == 8
    assert cfg.last_error is None
    assert cfg.last_success_at is not None


def test_deliver_batch_once_truncates_long_error_to_500_chars():
    cfg = _cfg()
    events = [_event(1)]
    long_err = "x" * 1000

    snap_returned = False

    def fake_run_db(coro_fn):
        nonlocal snap_returned
        if not snap_returned:
            snap_returned = True
            return _read_response(cfg, events)
        session = MagicMock()
        execute_result = MagicMock()
        execute_result.scalar_one.return_value = cfg
        session.execute = AsyncMock(return_value=execute_result)
        _drive_coro_in_isolated_loop(coro_fn, session)
        return None

    async def fake_webhook(url, token, payload, transport=None):
        return {"ok": False, "error": long_err}

    with patch("src.audit_stream.poster.run_db", side_effect=fake_run_db), \
         patch("src.audit_stream.poster.webhook_deliver", new=fake_webhook):
        asyncio.run(poster.deliver_batch_once())

    assert cfg.last_error is not None
    assert len(cfg.last_error) <= 500




def test_event_to_dict_shape():
    evt = _event(42)
    serialized = poster._event_to_dict(evt)
    assert serialized["id"] == 42
    assert serialized["event_id"] == 42
    assert serialized["action"] == "test.poster"
    assert serialized["actor"]["id"] == "u-1"
    assert serialized["actor"]["username"] == "alice"
    assert serialized["actor"]["email"] == "alice@example.com"
    assert serialized["resource"]["type"] == "user"
    assert serialized["resource"]["id"] == "42"
    assert serialized["metadata"] == {"n": 42}


def test_event_to_dict_handles_null_metadata():
    evt = _event(1)
    evt.metadata_json = None
    serialized = poster._event_to_dict(evt)
    assert serialized["metadata"] == {}


def test_event_to_dict_handles_null_created_at():
    evt = _event(1)
    evt.created_at = None
    serialized = poster._event_to_dict(evt)
    assert serialized["timestamp"] is None




def test_poster_loop_exits_promptly_when_stop_event_set():
    stop = asyncio.Event()
    stop.set()  # request stop before the loop even starts

    async def fake_deliver():
        return {"delivered": 0, "skipped": True}

    async def _run():
        with patch("src.audit_stream.poster.deliver_batch_once", new=fake_deliver):
            await asyncio.wait_for(poster.poster_loop(stop), timeout=2.0)

    asyncio.run(_run())


def test_sleep_or_stop_returns_promptly_when_event_set():
    async def _run():
        stop = asyncio.Event()
        stop.set()
        # If this hangs, the test will time out — proves the event short-circuits.
        await asyncio.wait_for(poster._sleep_or_stop(60.0, stop), timeout=1.0)
    asyncio.run(_run())


def test_sleep_or_stop_returns_after_timeout_when_event_unset():
    async def _run():
        stop = asyncio.Event()
        # Tiny timeout to keep the test fast.
        await poster._sleep_or_stop(0.01, stop)
    asyncio.run(_run())




def test_poster_loop_progresses_backoff_on_consecutive_failures():
    """First failure → BACKOFF_STEPS[0], second → STEPS[1], etc."""
    stop = asyncio.Event()
    deliver_call_count = {"n": 0}
    sleep_durations: list[float] = []

    async def fake_deliver():
        deliver_call_count["n"] += 1
        # After enough failures recorded, signal stop.
        if deliver_call_count["n"] >= 4:
            stop.set()
        return {"delivered": 0, "skipped": False, "error": "down"}

    async def fake_sleep(seconds, event):
        sleep_durations.append(seconds)

    async def _run():
        with patch("src.audit_stream.poster.deliver_batch_once", new=fake_deliver), \
             patch("src.audit_stream.poster._sleep_or_stop", new=fake_sleep):
            await asyncio.wait_for(poster.poster_loop(stop), timeout=2.0)

    asyncio.run(_run())

    # First four sleeps should match BACKOFF_STEPS_SECONDS.
    assert sleep_durations[:4] == [1, 5, 30, 300]


def test_poster_loop_resets_backoff_after_success():
    """A successful delivery should reset the backoff index."""
    stop = asyncio.Event()
    deliver_calls = {"n": 0}
    sleep_durations: list[float] = []

    async def fake_deliver():
        deliver_calls["n"] += 1
        # Two failures, then a success, then a failure.
        if deliver_calls["n"] in (1, 2):
            return {"delivered": 0, "skipped": False, "error": "fail"}
        if deliver_calls["n"] == 3:
            return {"delivered": 1, "skipped": False}
        if deliver_calls["n"] == 4:
            stop.set()
            return {"delivered": 0, "skipped": False, "error": "fail-again"}
        return {"delivered": 0, "skipped": True}

    async def fake_sleep(seconds, event):
        sleep_durations.append(seconds)

    async def _run():
        with patch("src.audit_stream.poster.deliver_batch_once", new=fake_deliver), \
             patch("src.audit_stream.poster._sleep_or_stop", new=fake_sleep):
            await asyncio.wait_for(poster.poster_loop(stop), timeout=2.0)

    asyncio.run(_run())

    # After 2 fails then 1 success, the next fail should restart at BACKOFF_STEPS[0]=1.
    assert sleep_durations[0] == 1
    assert sleep_durations[1] == 5
    assert sleep_durations[2] == poster.POLL_INTERVAL_SECONDS
    assert sleep_durations[3] == 1




def test_batch_size_constant_caps_per_loop_delivery():
    """BATCH_SIZE controls how many events leave the DB per loop iteration.

    Regression check: this constant gates DB query LIMIT and downstream payload
    size. If lowered to 1, single-event delivery still works; if raised, large
    in-memory batches risk OOM at the destination.
    """
    assert poster.BATCH_SIZE == 100




def test_webhook_omits_authorization_header_when_no_token():
    import httpx

    from src.audit_stream.adapters import webhook_deliver

    captured = {}

    def handler(req: httpx.Request) -> httpx.Response:
        captured["headers"] = dict(req.headers)
        return httpx.Response(200)

    transport = httpx.MockTransport(handler)
    result = asyncio.run(webhook_deliver(
        url="https://hook.example.com/x",
        token=None,
        events=[{"id": 1}],
        transport=transport,
    ))
    assert result["ok"] is True
    assert "authorization" not in captured["headers"]


def test_webhook_sets_bearer_authorization_header_when_token_present():
    import httpx

    from src.audit_stream.adapters import webhook_deliver

    captured = {}

    def handler(req: httpx.Request) -> httpx.Response:
        captured["auth"] = req.headers.get("authorization")
        return httpx.Response(200)

    transport = httpx.MockTransport(handler)
    asyncio.run(webhook_deliver(
        url="https://hook.example.com/x",
        token="bearer-xyz",
        events=[{"id": 1}],
        transport=transport,
    ))
    assert captured["auth"] == "Bearer bearer-xyz"


def test_splunk_body_is_newline_delimited_json():
    import httpx
    import json

    from src.audit_stream.adapters import splunk_hec_deliver

    captured = {}

    def handler(req: httpx.Request) -> httpx.Response:
        captured["body"] = req.content.decode()
        return httpx.Response(200)

    transport = httpx.MockTransport(handler)
    asyncio.run(splunk_hec_deliver(
        url="https://splunk.example.com:8088",
        token="t",
        events=[{"id": 1}, {"id": 2}, {"id": 3}],
        transport=transport,
    ))
    lines = captured["body"].split("\n")
    assert len(lines) == 3
    parsed = [json.loads(line) for line in lines]
    assert [p["id"] for p in parsed] == [1, 2, 3]


def test_syslog_rejects_url_without_port():
    from src.audit_stream.adapters import syslog_deliver

    result = asyncio.run(syslog_deliver(
        url="logs.example.com",
        token=None,
        events=[{"id": 1}],
    ))
    assert result["ok"] is False
    assert "host:port" in result["error"]


def test_syslog_rejects_non_numeric_port():
    from src.audit_stream.adapters import syslog_deliver

    result = asyncio.run(syslog_deliver(
        url="logs.example.com:not-a-port",
        token=None,
        events=[{"id": 1}],
    ))
    assert result["ok"] is False


def test_deliver_test_event_requires_target_type():
    from src.audit_stream.adapters import deliver_test_event

    cfg = _cfg(target_type=None)
    result = asyncio.run(deliver_test_event(cfg))
    assert result["ok"] is False
    assert "required" in result["error"].lower()


def test_deliver_test_event_routes_by_target_type():
    from src.audit_stream.adapters import deliver_test_event

    calls = {"webhook": 0, "splunk": 0}

    async def fake_webhook(url, token, events, transport=None):
        calls["webhook"] += 1
        return {"ok": True, "error": None}

    async def fake_splunk(url, token, events, transport=None):
        calls["splunk"] += 1
        return {"ok": True, "error": None}

    with patch("src.audit_stream.adapters.webhook_deliver", new=fake_webhook), \
         patch("src.audit_stream.adapters.splunk_hec_deliver", new=fake_splunk):
        cfg = _cfg(target_type="webhook")
        asyncio.run(deliver_test_event(cfg))
        cfg2 = _cfg(target_type="splunk_hec", endpoint_url="https://splunk.example.com:8088")
        asyncio.run(deliver_test_event(cfg2))

    assert calls == {"webhook": 1, "splunk": 1}


def test_deliver_test_event_decrypts_configured_token():
    """When auth_token_enc is set, the test event uses the decrypted plaintext."""
    from src.audit_stream.adapters import deliver_test_event

    captured = {}

    async def fake_webhook(url, token, events, transport=None):
        captured["token"] = token
        return {"ok": True, "error": None}

    with patch("src.audit_stream.adapters.webhook_deliver", new=fake_webhook):
        cfg = _cfg(auth_token_enc=encrypt("rotation-safe-token"))
        asyncio.run(deliver_test_event(cfg))

    assert captured["token"] == "rotation-safe-token"


def test_deliver_test_event_unknown_target_returns_error():
    from src.audit_stream.adapters import deliver_test_event

    cfg = _cfg(target_type="kafka")
    result = asyncio.run(deliver_test_event(cfg))
    assert result["ok"] is False
    assert "Unknown" in result["error"]




def test_encrypted_token_does_not_leak_plaintext_in_ciphertext():
    """Defense-in-depth: ciphertext must not embed the plaintext token."""
    plaintext = "very-sensitive-bearer-token-9876"
    ciphertext = encrypt(plaintext)
    assert plaintext not in ciphertext


def test_decrypt_token_with_wrong_key_raises(monkeypatch):
    """Key-rotation safety: decryption with the wrong key must fail loudly,
    not silently return garbage."""
    from src.security.crypto import decrypt
    from src.shared import encryption

    ciphertext = encrypt("token-under-key-A")
    # Rotate the root away so it can no longer decrypt the ciphertext.
    monkeypatch.setenv("APP_SECRET", "a-different-root-secret-for-rotation-test")
    encryption._reset_cache_for_tests()
    try:
        with pytest.raises(RuntimeError, match="decryption failed"):
            decrypt(ciphertext)
    finally:
        encryption._reset_cache_for_tests()


# ── idempotency: per-row event_id + replay-on-lost-ack ───────────────────────


@pytest.fixture(autouse=True)
def _clear_batch_hash_cache():
    """Module-level cache must not leak between tests."""
    poster._recent_batch_hashes.clear()
    yield
    poster._recent_batch_hashes.clear()


def test_outbound_payload_carries_event_id_per_row():
    """Every row in the POSTed payload must include event_id = audit_events.id."""
    cfg = _cfg()
    events = [_event(101), _event(102), _event(103)]

    calls = {"n": 0}

    def fake_run_db(coro_fn):
        calls["n"] += 1
        if calls["n"] == 1:
            return _read_response(cfg, events)
        return None

    captured: dict = {}

    async def fake_webhook(url, token, payload, transport=None):
        captured["payload"] = payload
        return {"ok": True, "error": None}

    with patch("src.audit_stream.poster.run_db", side_effect=fake_run_db), \
         patch("src.audit_stream.poster.webhook_deliver", new=fake_webhook):
        asyncio.run(poster.deliver_batch_once())

    sent = captured["payload"]
    assert len(sent) == 3
    assert [row["event_id"] for row in sent] == [101, 102, 103]
    # Every row must have event_id present (and non-null).
    assert all("event_id" in row and row["event_id"] is not None for row in sent)


def test_replay_after_lost_ack_resends_same_event_ids():
    """Simulate: POST succeeds, ack lost (write fails), poster restarts.

    The second tick must redeliver the identical batch with stable event_ids,
    so the receiver can dedup.
    """
    cfg = _cfg(last_event_id=10)
    events = [_event(11), _event(12)]

    posted_payloads: list[list[dict]] = []

    async def fake_webhook(url, token, payload, transport=None):
        # Deep-copy via JSON round-trip to capture an immutable snapshot.
        posted_payloads.append(json.loads(json.dumps(payload)))
        return {"ok": True, "error": None}

    # ── Tick 1: POST succeeds, but the cursor-write side crashes (lost ack). ──
    snap_returned_1 = False

    def fake_run_db_1(coro_fn):
        nonlocal snap_returned_1
        if not snap_returned_1:
            snap_returned_1 = True
            return _read_response(cfg, events)
        # Simulate the ack-loss / write crash: do nothing. The cursor stays at 10.
        raise RuntimeError("simulated write crash after successful POST")

    with patch("src.audit_stream.poster.run_db", side_effect=fake_run_db_1), \
         patch("src.audit_stream.poster.webhook_deliver", new=fake_webhook):
        with pytest.raises(RuntimeError, match="simulated write crash"):
            asyncio.run(poster.deliver_batch_once())

    # Simulate a fresh process: clear the module-level cache.
    poster._recent_batch_hashes.clear()

    # ── Tick 2: poster restarts; cursor still at 10; same batch is re-read. ──
    snap_returned_2 = False

    def fake_run_db_2(coro_fn):
        nonlocal snap_returned_2
        if not snap_returned_2:
            snap_returned_2 = True
            return _read_response(cfg, events)
        return None  # successful no-op write

    with patch("src.audit_stream.poster.run_db", side_effect=fake_run_db_2), \
         patch("src.audit_stream.poster.webhook_deliver", new=fake_webhook):
        asyncio.run(poster.deliver_batch_once())

    assert len(posted_payloads) == 2, "both ticks must POST (cache was cleared)"
    first_ids = [row["event_id"] for row in posted_payloads[0]]
    second_ids = [row["event_id"] for row in posted_payloads[1]]
    assert first_ids == second_ids == [11, 12]


def test_batch_hash_cache_short_circuits_in_process_replay():
    """If the cursor-write fails but the in-process cache survives, the next
    tick must skip the re-POST and just advance the cursor."""
    cfg = _cfg(last_event_id=20)
    events = [_event(21), _event(22)]

    post_count = {"n": 0}

    async def fake_webhook(url, token, payload, transport=None):
        post_count["n"] += 1
        return {"ok": True, "error": None}

    # ── Tick 1: POST succeeds, write side crashes (cursor stuck). ────────────
    snap_returned_1 = False

    def fake_run_db_1(coro_fn):
        nonlocal snap_returned_1
        if not snap_returned_1:
            snap_returned_1 = True
            return _read_response(cfg, events)
        raise RuntimeError("simulated write crash after successful POST")

    with patch("src.audit_stream.poster.run_db", side_effect=fake_run_db_1), \
         patch("src.audit_stream.poster.webhook_deliver", new=fake_webhook):
        with pytest.raises(RuntimeError):
            asyncio.run(poster.deliver_batch_once())

    # Cache must survive across ticks within the same process — that's the
    # whole point of the in-memory short-circuit.
    assert len(poster._recent_batch_hashes) == 1, \
        "successful POST must seed the cache before the write attempt"

    posts_before_tick2 = post_count["n"]

    # ── Tick 2: same range re-read; cache should short-circuit the POST. ─────
    snap_returned_2 = False
    write_advanced_to: list[int] = []

    def fake_run_db_2(coro_fn):
        nonlocal snap_returned_2
        if not snap_returned_2:
            snap_returned_2 = True
            return _read_response(cfg, events)
        # Drive the write with a fake session so we can observe cursor advancement.
        session = MagicMock()
        execute_result = MagicMock()
        execute_result.scalar_one.return_value = cfg
        session.execute = AsyncMock(return_value=execute_result)
        _drive_coro_in_isolated_loop(coro_fn, session)
        write_advanced_to.append(cfg.last_event_id)
        return None

    with patch("src.audit_stream.poster.run_db", side_effect=fake_run_db_2), \
         patch("src.audit_stream.poster.webhook_deliver", new=fake_webhook):
        result = asyncio.run(poster.deliver_batch_once())

    assert post_count["n"] == posts_before_tick2, "second tick must not re-POST"
    assert result.get("deduped") is True
    assert write_advanced_to == [22], "cursor must advance even when deduped"


def test_json_default_handles_temporal_and_uuid_types():
    """_batch_hash must serialise datetime/date/UUID deterministically (ISO /
    str), not via repr(), so the dedup hash is stable across ticks."""
    from datetime import datetime, date, timezone
    from uuid import UUID

    dt = datetime(2026, 6, 28, 12, 0, tzinfo=timezone.utc)
    assert poster._json_default(dt) == dt.isoformat()
    assert poster._json_default(date(2026, 6, 28)) == "2026-06-28"
    uid = UUID("12345678-1234-5678-1234-567812345678")
    assert poster._json_default(uid) == str(uid)


def test_json_default_raises_on_unknown_type():
    """A new non-serialisable payload type must fail loudly here rather than
    silently degrade dedup via a repr-with-address fallback."""
    import pytest as _pytest

    class _Weird:
        pass

    with _pytest.raises(TypeError):
        poster._json_default(_Weird())
