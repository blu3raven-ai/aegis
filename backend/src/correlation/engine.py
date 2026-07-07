"""CorrelationEngine — subscribe-dispatch-idempotency loop.

Subscribes to the durable Redis Streams event bus and dispatches each event
to all matching rules. Rules run synchronously inside the dispatch call.

The engine ships DORMANT: start() is callable but nothing in the production
app startup calls it yet. Wiring is gated by AEGIS_CORRELATION_ENABLED=true
and is a separate "flip the switch" follow-up.

Thread safety: start() launches a single daemon thread running the subscribe
loop. stop() signals it to exit cleanly.
"""
from __future__ import annotations

import logging
import threading
import time
from collections import defaultdict
from typing import Any

import redis

from src.argus.connector import ArgusConnector, get_argus_connector
from src.correlation.chain_graph_store import ChainGraphStore
from src.correlation.emit_interface import EmitInterface
from src.correlation.rule import Rule, RuleContext
from src.correlation.rule_pack_loader import RulePackLoader
from src.correlation.state import CorrelationState
from src.shared.event_stream import EventStream

logger = logging.getLogger(__name__)

# Consumer group used for all correlation engine subscriptions.
# Must be stable across restarts so the engine resumes from its last position.
_CONSUMER_GROUP = "aegis-correlation"

# Streams (event type prefixes) the engine subscribes to
_SUBSCRIBED_STREAMS = [
    "code.push",
    "code.file_save",
    "intel.cve_published",
    "intel.epss_changed",
    "scan.finding",
]

# After this many consecutive rule failures the rule is disabled and an alert
# is logged. An admin must restart the engine to re-enable disabled rules.
_CIRCUIT_BREAKER_THRESHOLD = 3

# How long to block waiting for events on each stream poll (milliseconds)
_BLOCK_MS = 500

# How many events to fetch per poll per stream
_BATCH_SIZE = 50


class _CircuitBreaker:
    """Per-rule failure counter with open/closed state."""

    def __init__(self, threshold: int) -> None:
        self._threshold = threshold
        self._failures: dict[str, int] = defaultdict(int)
        self._open: set[str] = set()

    def record_success(self, rule_name: str) -> None:
        self._failures[rule_name] = 0

    def record_failure(self, rule_name: str) -> bool:
        """Returns True if the circuit just tripped open."""
        self._failures[rule_name] += 1
        if self._failures[rule_name] >= self._threshold:
            if rule_name not in self._open:
                self._open.add(rule_name)
                return True
        return False

    def is_open(self, rule_name: str) -> bool:
        return rule_name in self._open

    def reset(self, rule_name: str) -> None:
        self._failures[rule_name] = 0
        self._open.discard(rule_name)


class CorrelationEngine:
    """Dispatches events from the durable bus to registered rules.

    Usage (production — dormant until enabled):
        engine = CorrelationEngine(stream_cfg, redis_cfg)
        engine.register_rule(IntelMatchRule())
        # engine.start() called only when AEGIS_CORRELATION_ENABLED=true

    Usage in tests (sync dispatch, no background thread):
        engine = CorrelationEngine(stream_cfg, redis_cfg)
        engine.register_rule(MyRule())
        engine.dispatch_event(raw_event_dict)
    """

    def __init__(
        self,
        stream_config: dict[str, Any],
        redis_config: dict[str, Any],
        *,
        consumer_name: str = "engine-0",
        argus: ArgusConnector | None = None,
    ) -> None:
        self._stream_cfg = stream_config
        self._redis_cfg = redis_config
        self._consumer_name = consumer_name
        # When no connector is supplied, build one from env so rules always
        # receive a working connector with heuristic fallbacks.
        self._argus: ArgusConnector = argus if argus is not None else get_argus_connector()

        self._event_stream = EventStream(stream_config)
        self._redis = redis.Redis.from_url(redis_config["url"])
        self._chain_store = ChainGraphStore()
        self._state = CorrelationState()
        self._emit = EmitInterface(self._redis, self._chain_store)

        # rule_name → Rule; triggers → [rule_name]
        self._rules: dict[str, Rule] = {}
        self._trigger_index: dict[str, list[str]] = defaultdict(list)

        self._breaker = _CircuitBreaker(_CIRCUIT_BREAKER_THRESHOLD)
        # Held during reload_rules() to prevent concurrent dispatch + index swap
        self._reload_lock = threading.Lock()

        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None

    # ── rule registration ─────────────────────────────────────────────────────

    def register_rule(self, rule: Rule) -> None:
        """Add a rule to the engine. Safe to call before start()."""
        self._rules[rule.name] = rule
        for trigger in rule.triggers:
            if rule.name not in self._trigger_index[trigger]:
                self._trigger_index[trigger].append(rule.name)
        logger.info("correlation.engine: registered rule %s (triggers=%s)",
                    rule.name, rule.triggers)

    def reload_rules(self, loader: RulePackLoader | None = None) -> int:
        """Hot-reload rules from all configured packs without restarting the engine.

        Briefly pauses dispatch by holding the reload lock, rebuilds the trigger
        index, then resumes. In-flight dispatch calls that already hold the lock
        are drained first. Returns the number of packs loaded.

        loader defaults to a fresh RulePackLoader seeded with the engine's Argus
        connector. Pass a custom loader in tests.
        """
        if loader is None:
            loader = RulePackLoader(argus_connector=self._argus)
            loader.load_builtin()
            loader.load_from_argus()

        with self._reload_lock:
            new_rules: dict[str, Rule] = {}
            new_index: dict[str, list[str]] = defaultdict(list)

            for rule in loader.get_all_rules():
                new_rules[rule.name] = rule
                for trigger in rule.triggers:
                    new_index[trigger].append(rule.name)
                # Preserve circuit-breaker state across reloads so a flapping rule
                # does not reset its failure count just by being reloaded.

            self._rules = new_rules
            self._trigger_index = new_index

        logger.info(
            "correlation.engine: reloaded %d rule(s) from %d pack(s)",
            len(new_rules), loader.pack_count,
        )
        return loader.pack_count

    # ── lifecycle ─────────────────────────────────────────────────────────────

    def start(self) -> None:
        """Launch the background subscribe loop. No-op if already running."""
        if self._thread and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run_loop,
            name="correlation-engine",
            daemon=True,
        )
        self._thread.start()
        logger.info("correlation.engine: started (consumer=%s)", self._consumer_name)

    def stop(self, timeout: float = 5.0) -> None:
        """Signal the loop to stop and wait for the thread to exit."""
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=timeout)
        logger.info("correlation.engine: stopped")

    @property
    def is_running(self) -> bool:
        return bool(self._thread and self._thread.is_alive())

    # ── sync dispatch (used in tests and by the loop) ─────────────────────────

    def dispatch_event(self, raw_event: dict[str, Any]) -> None:
        """Dispatch a single raw event dict to all matching rules.

        raw_event is the dict yielded by EventStream.subscribe().
        Holds _reload_lock shared with reload_rules() to prevent reading a
        partially-swapped trigger index.
        """
        with self._reload_lock:
            event_type = raw_event.get("event_type", "")
            rule_names = list(self._trigger_index.get(event_type, []))
            rules_snapshot = {n: self._rules[n] for n in rule_names if n in self._rules}

        ctx = RuleContext(
            state=self._state,
            argus=self._argus,
            emit=self._emit,
        )

        for rule_name, rule in rules_snapshot.items():
            if self._breaker.is_open(rule_name):
                logger.debug("correlation.engine: skipping disabled rule %s", rule_name)
                continue
            try:
                rule.evaluate(raw_event, ctx)
                self._breaker.record_success(rule_name)
            except Exception:
                tripped = self._breaker.record_failure(rule_name)
                logger.exception(
                    "correlation.engine: rule %s failed on event %s",
                    rule_name, raw_event.get("event_id"),
                )
                if tripped:
                    logger.critical(
                        "correlation.engine: rule %s DISABLED after %d consecutive failures; "
                        "admin action required to re-enable",
                        rule_name, _CIRCUIT_BREAKER_THRESHOLD,
                    )

    # ── subscribe loop ────────────────────────────────────────────────────────

    def _run_loop(self) -> None:
        """Background thread body: poll streams and dispatch events."""
        while not self._stop_event.is_set():
            for event_type in _SUBSCRIBED_STREAMS:
                if self._stop_event.is_set():
                    break
                # Only poll streams that have at least one registered rule
                if not self._trigger_index.get(event_type):
                    continue
                try:
                    for raw_event in self._event_stream.subscribe(
                        event_type=event_type,
                        group=_CONSUMER_GROUP,
                        consumer=self._consumer_name,
                        block_ms=_BLOCK_MS,
                        count=_BATCH_SIZE,
                        start_at_new=True,
                    ):
                        self.dispatch_event(raw_event)
                        self._event_stream.ack(
                            event_type, _CONSUMER_GROUP, raw_event["_stream_id"]
                        )
                except Exception:
                    logger.exception(
                        "correlation.engine: error polling stream %s; will retry",
                        event_type,
                    )
                    time.sleep(1)
