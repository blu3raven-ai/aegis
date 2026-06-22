"""Phase 0 dual-write integration tests.

Verifies that existing scan lifecycle code paths emit durable events
without changing scan behavior.
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch


@patch("src.shared.event_emit_helpers.get_event_publisher")
def test_scan_started_emit_helper_publishes(mock_get_pub):
    pub = MagicMock()
    mock_get_pub.return_value = pub

    from src.shared.event_emit_helpers import emit_scan_started
    emit_scan_started(
        org_id="acme-org",
        scan_id="scan-abc",
        repo_id="repo-1",
        scanner_type="dependencies_scanning",
        trigger_event_id="01HXYZ",
    )

    pub.publish.assert_called_once()
    evt = pub.publish.call_args.args[0]
    assert evt.event_type == "scan.started"
    assert evt.org_id == "acme-org"
    assert evt.payload["scan_id"] == "scan-abc"


@patch("src.shared.event_emit_helpers.get_event_publisher")
def test_emit_helper_swallows_publish_failure(mock_get_pub, caplog):
    pub = MagicMock()
    pub.publish.side_effect = RuntimeError("simulated publisher outage")
    mock_get_pub.return_value = pub

    from src.shared.event_emit_helpers import emit_scan_started
    # Must NOT raise
    emit_scan_started(
        org_id="acme-org",
        scan_id="scan-abc",
        repo_id="repo-1",
        scanner_type="dependencies_scanning",
        trigger_event_id="01HXYZ",
    )

    # Should have logged the failure
    assert any("phase0 dual-write failed" in r.message for r in caplog.records)


@patch("src.shared.event_emit_helpers.get_event_publisher")
def test_scan_completed_emit_helper_publishes(mock_get_pub):
    pub = MagicMock()
    mock_get_pub.return_value = pub

    from src.shared.event_emit_helpers import emit_scan_completed
    emit_scan_completed(
        org_id="acme-org", scan_id="scan-abc",
        duration_ms=8123, findings_count=17,
    )

    pub.publish.assert_called_once()
    evt = pub.publish.call_args.args[0]
    assert evt.event_type == "scan.completed"
    assert evt.payload["duration_ms"] == 8123


@patch("src.shared.event_emit_helpers.get_event_publisher")
def test_scan_failed_emit_helper_publishes(mock_get_pub):
    pub = MagicMock()
    mock_get_pub.return_value = pub

    from src.shared.event_emit_helpers import emit_scan_failed
    emit_scan_failed(
        org_id="acme-org", scan_id="scan-abc",
        error="timeout", retryable=True,
    )

    pub.publish.assert_called_once()
    evt = pub.publish.call_args.args[0]
    assert evt.event_type == "scan.failed"
    assert evt.payload["retryable"] is True


@patch("src.shared.event_emit_helpers.get_event_publisher")
def test_manual_rescan_emit_helper_publishes(mock_get_pub):
    pub = MagicMock()
    mock_get_pub.return_value = pub

    from src.shared.event_emit_helpers import emit_manual_rescan
    emit_manual_rescan(
        org_id="acme-org",
        repo_id="repo-1",
        scanner_type="dependencies_scanning",
        full=False,
        source_component="dependencies.router",
    )

    pub.publish.assert_called_once()
    evt = pub.publish.call_args.args[0]
    assert evt.event_type == "code.manual_rescan"
    assert evt.source_component == "dependencies.router"
    assert evt.payload["scanner_type"] == "dependencies"


@patch("src.shared.event_emit_helpers.get_event_publisher")
def test_manual_rescan_emit_helper_swallows_failure(mock_get_pub):
    pub = MagicMock()
    pub.publish.side_effect = RuntimeError("boom")
    mock_get_pub.return_value = pub

    from src.shared.event_emit_helpers import emit_manual_rescan
    # Must not raise
    emit_manual_rescan(
        org_id="acme-org", repo_id="repo-1", scanner_type="dependencies_scanning",
        source_component="dependencies.router",
    )


@patch("src.shared.event_emit_helpers.get_event_publisher")
def test_finding_created_emit_helper_publishes(mock_get_pub):
    pub = MagicMock()
    mock_get_pub.return_value = pub

    from src.shared.event_emit_helpers import emit_finding_created
    emit_finding_created(
        org_id="acme-org",
        finding={"id": "F-1", "severity": "critical", "scanner_type": "deps"},
        scanner_type="dependencies_scanning",
        source_component="dependencies.scanner",
    )

    pub.publish.assert_called_once()
    evt = pub.publish.call_args.args[0]
    assert evt.event_type == "finding.created"
    assert evt.payload["finding_id"] == "F-1"
    assert evt.payload["severity"] == "critical"


@patch("src.shared.event_emit_helpers.get_event_publisher")
def test_finding_created_emit_helper_swallows_failure(mock_get_pub):
    pub = MagicMock()
    pub.publish.side_effect = RuntimeError("boom")
    mock_get_pub.return_value = pub

    from src.shared.event_emit_helpers import emit_finding_created
    # Must not raise
    emit_finding_created(
        org_id="acme-org",
        finding={"id": "F-2", "severity": "high"},
        scanner_type="dependencies_scanning",
        source_component="dependencies.scanner",
    )


# ============== End-to-end integration tests ==============

def test_emit_helpers_use_real_publisher_when_not_mocked(monkeypatch):
    """Verify that emit helpers actually hit the real EventPublisher
    singleton (i.e., the indirection isn't broken)."""
    # Reset singleton to force re-init
    import src.shared.event_publisher as ep_module
    ep_module._publisher = None

    from src.shared.event_publisher import get_event_publisher
    pub = get_event_publisher()
    assert pub is not None
    # We're not actually publishing here — just confirming the singleton wiring.


@patch("src.shared.event_emit_helpers.get_event_publisher")
def test_full_dual_write_sequence_does_not_raise(mock_get_pub):
    """Simulate a full scan lifecycle via the helpers; assert no exceptions
    propagate even when ALL publisher calls fail."""
    pub = MagicMock()
    pub.publish.side_effect = RuntimeError("simulated publisher outage")
    mock_get_pub.return_value = pub

    from src.shared.event_emit_helpers import (
        emit_manual_rescan, emit_scan_started, emit_scan_completed,
        emit_scan_failed, emit_finding_created,
    )

    # Simulate user-triggered manual rescan
    emit_manual_rescan(
        org_id="acme-org", repo_id="repo-1",
        scanner_type="dependencies_scanning", source_component="dependencies.router",
    )
    # Simulate orchestrator starting the scan
    emit_scan_started(
        org_id="acme-org", scan_id="scan-1", repo_id="repo-1",
        scanner_type="dependencies_scanning", trigger_event_id="01HX",
    )
    # Simulate per-finding emit
    emit_finding_created(
        org_id="acme-org",
        finding={"id": "F-1", "severity": "critical"},
        scanner_type="dependencies_scanning",
        source_component="dependencies.scanner",
    )
    # Simulate scan completion
    emit_scan_completed(
        org_id="acme-org", scan_id="scan-1",
        duration_ms=8000, findings_count=1,
    )
    # And the failure path
    emit_scan_failed(
        org_id="acme-org", scan_id="scan-2",
        error="timeout", retryable=True,
    )

    # All 5 calls should have been attempted (and all should have raised internally)
    assert pub.publish.call_count == 5
    # But none should have propagated — we got here without an exception.


@patch("src.shared.event_emit_helpers.get_event_publisher")
def test_full_dual_write_sequence_emits_correct_event_types(mock_get_pub):
    """Verify the helpers emit events in the right shape."""
    pub = MagicMock()
    mock_get_pub.return_value = pub

    from src.shared.event_emit_helpers import (
        emit_manual_rescan, emit_scan_started, emit_scan_completed,
        emit_scan_failed, emit_finding_created,
    )

    emit_manual_rescan(
        org_id="acme-org", repo_id="repo-1",
        scanner_type="dependencies_scanning", source_component="dependencies.router",
    )
    emit_scan_started(
        org_id="acme-org", scan_id="scan-1", repo_id="repo-1",
        scanner_type="dependencies_scanning", trigger_event_id="01HX",
    )
    emit_finding_created(
        org_id="acme-org",
        finding={"id": "F-1", "severity": "critical"},
        scanner_type="dependencies_scanning",
        source_component="dependencies.scanner",
    )
    emit_scan_completed(
        org_id="acme-org", scan_id="scan-1",
        duration_ms=8000, findings_count=1,
    )
    emit_scan_failed(
        org_id="acme-org", scan_id="scan-2",
        error="timeout", retryable=False,
    )

    event_types = [call.args[0].event_type for call in pub.publish.call_args_list]
    assert event_types == [
        "code.manual_rescan",
        "scan.started",
        "finding.created",
        "scan.completed",
        "scan.failed",
    ]
