"""Tests for shared event type base class."""
from __future__ import annotations

import datetime
import json

import pytest
from pydantic import ValidationError

from src.shared.event_types.base import Event


def test_event_has_ulid_event_id_by_default():
    e = Event(event_type="test.event", org_id="acme-org", payload={"k": "v"})
    assert len(e.event_id) == 26
    # ULIDs are time-sortable; first 10 chars are timestamp component
    assert e.event_id.isalnum()


def test_event_has_utc_timestamp_by_default():
    e = Event(event_type="test.event", org_id="acme-org", payload={"k": "v"})
    assert e.timestamp_utc.tzinfo == datetime.timezone.utc


def test_event_serializes_to_json_round_trip():
    e = Event(event_type="test.event", org_id="acme-org", payload={"k": "v"})
    payload = e.model_dump_json()
    restored = Event.model_validate_json(payload)
    assert restored.event_id == e.event_id
    assert restored.event_type == e.event_type
    assert restored.org_id == e.org_id
    assert restored.payload == e.payload


def test_event_requires_event_type():
    with pytest.raises(ValidationError):
        Event(org_id="acme-org", payload={})


def test_event_requires_org_id():
    with pytest.raises(ValidationError):
        Event(event_type="test.event", payload={})


from src.shared.event_types.code import (
    CodePushEvent,
    ImagePushEvent,
    PrOpenedEvent,
    PrUpdatedEvent,
    FileSaveEvent,
    ManualRescanEvent,
)


def test_code_push_event():
    e = CodePushEvent(
        org_id="acme-org",
        payload={
            "repo_id": "repo-123",
            "ref": "refs/heads/main",
            "before_sha": "0" * 40,
            "after_sha": "a" * 40,
            "commits": [{"sha": "a" * 40, "author": "user@example.org"}],
        },
    )
    assert e.event_type == "code.push"


def test_image_push_event():
    e = ImagePushEvent(
        org_id="acme-org",
        payload={
            "registry": "example.registry.local",
            "image": "payments-api",
            "digest": "sha256:" + "f" * 64,
            "previous_digest": None,
        },
    )
    assert e.event_type == "code.image_push"


def test_manual_rescan_event_with_scanner_filter():
    e = ManualRescanEvent(
        org_id="acme-org",
        payload={"repo_id": "repo-123", "scanner_type": "dependencies", "full": False},
    )
    assert e.event_type == "code.manual_rescan"


from src.shared.event_types.intel import (
    CvePublishedEvent,
    EpssChangedEvent,
    ExploitAvailabilityChangedEvent,
    RulePackUpdatedEvent,
)


def test_cve_published_event():
    e = CvePublishedEvent(
        org_id="acme-org",
        source_component="argus",
        payload={
            "cve_id": "CVE-2026-1234",
            "affected_packages": [{"name": "log4j", "version_range": "<2.17.2"}],
            "severity": "critical",
            "epss": 0.91,
        },
    )
    assert e.event_type == "intel.cve_published"
    assert e.source_component == "argus"


def test_epss_changed_event():
    e = EpssChangedEvent(
        org_id="acme-org",
        source_component="argus",
        payload={"cve_id": "CVE-2026-1234", "old_epss": 0.42, "new_epss": 0.91},
    )
    assert e.event_type == "intel.epss_changed"


def test_rule_pack_updated_event():
    e = RulePackUpdatedEvent(
        org_id="acme-org",
        source_component="argus",
        payload={"scanner_type": "sast", "version": "1.4.2", "hash": "deadbeef"},
    )
    assert e.event_type == "intel.rule_pack_updated"


from src.shared.event_types.scan import (
    ScanStartedEvent,
    ScanProgressEvent,
    ScanFindingEvent,
    ScanCompletedEvent,
    ScanFailedEvent,
)


def test_scan_started_event():
    e = ScanStartedEvent(
        org_id="acme-org",
        payload={
            "scan_id": "scan-abc",
            "repo_id": "repo-123",
            "scanner_type": "dependencies",
            "trigger_event_id": "01HX2K3...",
        },
    )
    assert e.event_type == "scan.started"


def test_scan_completed_event():
    e = ScanCompletedEvent(
        org_id="acme-org",
        payload={"scan_id": "scan-abc", "duration_ms": 8123, "findings_count": 17},
    )
    assert e.event_type == "scan.completed"


def test_scan_failed_event_with_retryable_flag():
    e = ScanFailedEvent(
        org_id="acme-org",
        payload={"scan_id": "scan-abc", "error": "timeout", "retryable": True},
    )
    assert e.event_type == "scan.failed"
    assert e.payload["retryable"] is True


from src.shared.event_types.finding import (
    FindingCreatedEvent,
    FindingSeverityChangedEvent,
    FindingMergedEvent,
    FindingClosedEvent,
    ChainCreatedEvent,
    ChainUpdatedEvent,
)


def test_finding_created_event():
    e = FindingCreatedEvent(
        org_id="acme-org",
        payload={"finding_id": "F-1", "severity": "critical", "scanner_type": "deps"},
    )
    assert e.event_type == "finding.created"


def test_chain_created_event():
    e = ChainCreatedEvent(
        org_id="acme-org",
        payload={
            "chain_id": "CH-1",
            "finding_ids": ["F-1", "F-2", "F-3"],
            "chain_type": "reachable_cve",
        },
    )
    assert e.event_type == "chain.created"


def test_chain_updated_with_edges_delta():
    e = ChainUpdatedEvent(
        org_id="acme-org",
        payload={
            "chain_id": "CH-1",
            "edges_added": [{"from": "F-1", "to": "F-2", "type": "taint"}],
            "edges_removed": [],
        },
    )
    assert e.event_type == "chain.updated"
