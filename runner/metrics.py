# runner/metrics.py
"""System and Prometheus metrics for the runner agent.

Two concerns live here:

1. System resource metrics (CPU, memory, disk) used in the heartbeat payload.
2. Prometheus metrics that expose runner observability for scraping.

Prometheus metrics are module-level singletons.  They accumulate in-process
and are served on RUNNER_METRICS_PORT (default: disabled) when set.
"""
from __future__ import annotations

# Prime CPU sampling so the first collect_metrics() call returns useful data.
try:
    import psutil as _psutil
    _psutil.cpu_percent(interval=None)
except ImportError:
    pass


def collect_metrics() -> dict:
    """Return CPU, memory, and disk metrics for the heartbeat payload."""
    try:
        import psutil
    except ImportError:
        return {}

    cpu = psutil.cpu_percent(interval=None)
    mem = psutil.virtual_memory()
    disk = psutil.disk_usage("/")

    import platform
    return {
        "cpuPercent": cpu,
        "memoryUsedGb": round(mem.used / (1024**3), 2),
        "memoryTotalGb": round(mem.total / (1024**3), 2),
        "diskUsedGb": round(disk.used / (1024**3), 2),
        "diskTotalGb": round(disk.total / (1024**3), 2),
        "cores": psutil.cpu_count(logical=True),
        "os": platform.system().lower(),
        "arch": platform.machine(),
    }


# ---------------------------------------------------------------------------
# Prometheus metrics
# ---------------------------------------------------------------------------
# All metrics are wrapped in a try/except so the runner still starts if
# prometheus_client is absent (the dep is optional in minimal deployments).

try:
    from prometheus_client import Counter, Histogram

    jobs_processed_total = Counter(
        "aegis_runner_jobs_processed_total",
        "Total jobs processed by the runner, by scanner_type and status.",
        ["scanner_type", "status"],
    )

    job_duration_seconds = Histogram(
        "aegis_runner_job_duration_seconds",
        "Time to process one job end-to-end, by scanner_type.",
        ["scanner_type"],
        buckets=(1, 5, 10, 30, 60, 120, 300, 600, 1800, 3600),
    )

    # Time from job creation timestamp (as recorded by the backend) to when
    # the runner begins executing it.  Sub-second when subscription mode is
    # active; up to POLL_INTERVAL seconds in poll mode.
    job_pickup_latency_seconds = Histogram(
        "aegis_runner_job_pickup_latency_seconds",
        "Time from job creation to runner pickup.",
        ["scanner_type", "dispatch_mode"],
        buckets=(0.05, 0.1, 0.5, 1, 2, 5, 10, 30, 60),
    )

    _PROMETHEUS_AVAILABLE = True

except ImportError:
    # Provide no-op stubs so callers don't need to guard every metric call.
    class _Noop:  # type: ignore[misc]
        """Drop-in stub that ignores all method calls."""
        def labels(self, *_a, **_kw):  # noqa: ANN001
            return self
        def inc(self, *_a, **_kw) -> None: ...
        def observe(self, *_a, **_kw) -> None: ...
        def set(self, *_a, **_kw) -> None: ...

    _noop = _Noop()
    jobs_processed_total = _noop  # type: ignore[assignment]
    job_duration_seconds = _noop  # type: ignore[assignment]
    job_pickup_latency_seconds = _noop  # type: ignore[assignment]
    _PROMETHEUS_AVAILABLE = False


def start_metrics_server() -> None:
    """Start a Prometheus HTTP endpoint on RUNNER_METRICS_PORT.

    Does nothing when the env var is unset — keeps the default deployment
    footprint minimal.  Set RUNNER_METRICS_PORT=8000 to opt in.
    """
    import logging
    import os

    port_str = os.getenv("RUNNER_METRICS_PORT", "")
    if not port_str:
        return

    if not _PROMETHEUS_AVAILABLE:
        logging.getLogger(__name__).warning(
            "[metrics] prometheus_client not installed — metrics endpoint disabled"
        )
        return

    try:
        port = int(port_str)
        from prometheus_client import start_http_server
        start_http_server(port)
        logging.getLogger(__name__).info(
            "[metrics] Prometheus endpoint listening on :%d", port
        )
    except Exception as exc:
        logging.getLogger(__name__).error(
            "[metrics] Failed to start metrics server: %s", exc
        )
