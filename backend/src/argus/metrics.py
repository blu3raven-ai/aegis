"""Prometheus metrics for the Argus connector.

Follows the same naming convention as the shared event_metrics module
(prefix: aegis_argus_*). All instruments are module-level singletons so
there is exactly one registration per process.
"""
from __future__ import annotations

from prometheus_client import Counter, Gauge, Histogram

# Total requests to Argus, labelled by endpoint path and outcome status
argus_requests_total = Counter(
    "aegis_argus_requests_total",
    "Total requests to Argus by endpoint and status",
    ["endpoint", "status"],
)

# Latency distribution per endpoint
argus_request_duration_seconds = Histogram(
    "aegis_argus_request_duration_seconds",
    "Duration of Argus requests",
    ["endpoint"],
)

# Circuit breaker state encoded as a numeric gauge for dashboards
# 0 = closed (healthy), 1 = half_open (probing), 2 = open (failing fast)
argus_circuit_breaker_state = Gauge(
    "aegis_argus_circuit_breaker_state",
    "Circuit breaker state (0=closed, 1=half_open, 2=open)",
)

# Counts each heuristic fallback invocation and why it happened
argus_fallbacks_total = Counter(
    "aegis_argus_fallbacks_total",
    "Number of times heuristic fallback was used",
    ["reason"],  # 'unconfigured' | 'circuit_open' | 'timeout' | 'network_error' | 'http_error'
)

# Counts retry attempts so operators can see retry pressure per endpoint
argus_retries_total = Counter(
    "aegis_argus_retries_total",
    "Number of retry attempts by endpoint",
    ["endpoint"],
)

# Mapping from circuit breaker status string to numeric gauge value
_CIRCUIT_STATE_NUMERIC: dict[str, float] = {
    "closed": 0.0,
    "half_open": 1.0,
    "open": 2.0,
}


def update_circuit_state_gauge(status: str) -> None:
    """Update the circuit breaker state gauge on every state transition."""
    value = _CIRCUIT_STATE_NUMERIC.get(status, 0.0)
    argus_circuit_breaker_state.set(value)
