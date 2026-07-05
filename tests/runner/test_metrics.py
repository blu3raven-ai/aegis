"""Tests for runner Prometheus metrics: counters, histograms, and gauge wiring.

All tests are unit-level and run without Docker or a live backend.
Prometheus metrics are module-level singletons, so each test uses a fresh
CollectorRegistry to avoid cross-test pollution.
"""
from __future__ import annotations

import os
import sys
import time
from unittest.mock import patch

import pytest

# Make the runner/ directory importable.
_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, _ROOT)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _fresh_registry():
    """Return a new CollectorRegistry for isolated metric assertions."""
    from prometheus_client import CollectorRegistry
    return CollectorRegistry()


def _make_counter(name: str, labels: list[str], registry):
    from prometheus_client import Counter
    return Counter(name, "test counter", labels, registry=registry)


def _make_histogram(name: str, labels: list[str], registry, buckets=None):
    from prometheus_client import Histogram
    kw = {"registry": registry}
    if buckets:
        kw["buckets"] = buckets
    return Histogram(name, "test histogram", labels, **kw)


def _sample_value(metric, label_dict: dict):
    """Return the current value for a metric + label combination."""
    for sample in metric.collect()[0].samples:
        if sample.labels == label_dict:
            return sample.value
    return None


# ---------------------------------------------------------------------------
# Counter tests
# ---------------------------------------------------------------------------

class TestJobsProcessedCounter:
    def test_increments_on_success(self) -> None:
        reg = _fresh_registry()
        counter = _make_counter(
            "aegis_test_jobs_processed_total", ["scanner_type", "status"], reg
        )
        counter.labels(scanner_type="dependencies_scanning", status="success").inc()
        val = _sample_value(counter, {"scanner_type": "dependencies_scanning", "status": "success"})
        assert val == 1.0

    def test_increments_on_failure(self) -> None:
        reg = _fresh_registry()
        counter = _make_counter(
            "aegis_test_jobs_failed_total", ["scanner_type", "status"], reg
        )
        counter.labels(scanner_type="sast", status="failed").inc()
        val = _sample_value(counter, {"scanner_type": "sast", "status": "failed"})
        assert val == 1.0

    def test_multiple_scanner_types_independent(self) -> None:
        reg = _fresh_registry()
        counter = _make_counter(
            "aegis_test_multi_scanner_total", ["scanner_type", "status"], reg
        )
        counter.labels(scanner_type="dependencies_scanning", status="success").inc()
        counter.labels(scanner_type="dependencies_scanning", status="success").inc()
        counter.labels(scanner_type="secret_scanning", status="success").inc()

        deps_val = _sample_value(counter, {"scanner_type": "dependencies_scanning", "status": "success"})
        secrets_val = _sample_value(counter, {"scanner_type": "secret_scanning", "status": "success"})
        assert deps_val == 2.0
        assert secrets_val == 1.0

# ---------------------------------------------------------------------------
# Histogram tests
# ---------------------------------------------------------------------------

class TestJobDurationHistogram:
    def test_observe_records_duration(self) -> None:
        reg = _fresh_registry()
        hist = _make_histogram(
            "aegis_test_job_duration_seconds",
            ["scanner_type"],
            reg,
            buckets=(1, 5, 10, 60),
        )
        hist.labels(scanner_type="dependencies_scanning").observe(3.0)

        # Check _sum sample
        samples = {s.name: s.value for s in hist.collect()[0].samples
                   if s.labels == {"scanner_type": "dependencies_scanning", "le": "+Inf"}
                   or s.name.endswith("_sum") and s.labels == {"scanner_type": "dependencies_scanning"}}
        sum_sample = next(
            s.value for s in hist.collect()[0].samples
            if s.name.endswith("_sum") and s.labels == {"scanner_type": "dependencies_scanning"}
        )
        assert sum_sample == pytest.approx(3.0)

    def test_pickup_latency_histogram(self) -> None:
        reg = _fresh_registry()
        hist = _make_histogram(
            "aegis_test_pickup_latency",
            ["scanner_type", "dispatch_mode"],
            reg,
            buckets=(0.05, 0.5, 5, 30),
        )
        hist.labels(scanner_type="secret_scanning", dispatch_mode="poll").observe(0.3)

        sum_sample = next(
            s.value for s in hist.collect()[0].samples
            if s.name.endswith("_sum")
            and s.labels == {"scanner_type": "secret_scanning", "dispatch_mode": "poll"}
        )
        assert sum_sample == pytest.approx(0.3)

    def test_multiple_observations_accumulate(self) -> None:
        reg = _fresh_registry()
        hist = _make_histogram("aegis_test_accum", ["scanner_type"], reg)
        hist.labels(scanner_type="sast").observe(10.0)
        hist.labels(scanner_type="sast").observe(20.0)

        sum_sample = next(
            s.value for s in hist.collect()[0].samples
            if s.name.endswith("_sum") and s.labels == {"scanner_type": "sast"}
        )
        assert sum_sample == pytest.approx(30.0)


# ---------------------------------------------------------------------------
# Module-level metrics availability test
# ---------------------------------------------------------------------------

class TestMetricsModuleExports:
    def test_all_expected_metrics_exported(self) -> None:
        import runner.observability.metrics as m
        assert hasattr(m, "jobs_processed_total")
        assert hasattr(m, "job_duration_seconds")
        assert hasattr(m, "job_pickup_latency_seconds")
        assert hasattr(m, "start_metrics_server")
        assert hasattr(m, "collect_metrics")

    def test_start_metrics_server_noop_without_env(self) -> None:
        """start_metrics_server() must not bind a port when env var is absent."""
        import runner.observability.metrics as m
        # Should complete without error and without calling start_http_server.
        with patch("runner.observability.metrics._PROMETHEUS_AVAILABLE", True):
            with patch("prometheus_client.start_http_server") as mock_start:
                os.environ.pop("RUNNER_METRICS_PORT", None)
                m.start_metrics_server()
                mock_start.assert_not_called()

    def test_start_metrics_server_binds_when_port_set(self) -> None:
        import runner.observability.metrics as m
        with patch("runner.observability.metrics._PROMETHEUS_AVAILABLE", True):
            with patch("prometheus_client.start_http_server") as mock_start:
                os.environ["RUNNER_METRICS_PORT"] = "9090"
                try:
                    m.start_metrics_server()
                    mock_start.assert_called_once_with(9090)
                finally:
                    del os.environ["RUNNER_METRICS_PORT"]
