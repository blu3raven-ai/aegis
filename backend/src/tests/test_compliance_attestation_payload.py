from __future__ import annotations

import os

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost:5432/test")

from unittest.mock import patch  # noqa: E402

import pytest  # noqa: E402

from src.compliance.models import ControlSummaryItem, FindingBrief, Framework, FrameworkControl  # noqa: E402
from src.compliance.service import build_attestation_payload  # noqa: E402


async def _resolve_framework(_session, framework_id):
    label = {"soc2": "SOC 2", "iso27001": "ISO 27001", "pci-dss": "PCI DSS"}.get(framework_id, framework_id)
    return Framework(id=framework_id, label=label, is_custom=False)


def _control(control_id="CC6.1", title="Logical access", finding_count=0, sev=None):
    return ControlSummaryItem(
        framework="soc2",
        control_id=control_id,
        title=title,
        category="access",
        finding_count=finding_count,
        highest_severity=sev,
    )


def _brief(brief_id=1, severity="critical", tool="semgrep", org="acme", repo="api"):
    return FindingBrief(
        id=brief_id,
        tool=tool,
        org=org,
        repo=repo,
        severity=severity,
        state="open",
        identity_key=f"id-{brief_id}",
        confidence=0.9,
        rationale=None,
    )


@pytest.mark.asyncio
async def test_payload_shape_all_met():
    async def _summary(_session, _fw, *, asset_ids):
        return [_control(), _control(control_id="CC7.1", title="Change mgmt")]

    async def _findings(_session, _fw, _control_id, *, asset_ids):
        return []

    async def _controls(_session, _fw):
        return [
            FrameworkControl(
                framework="soc2",
                control_id="CC6.1",
                title="Logical access",
                description="Access controls",
                category="access",
            ),
            FrameworkControl(
                framework="soc2",
                control_id="CC7.1",
                title="Change mgmt",
                description=None,
                category="ops",
            ),
        ]

    with (
        patch("src.compliance.service.get_framework", side_effect=_resolve_framework),
        patch("src.compliance.service.get_framework_summary", side_effect=_summary),
        patch("src.compliance.service.get_findings_for_control", side_effect=_findings),
        patch("src.compliance.service.list_controls_for_framework", side_effect=_controls),
    ):
        payload = await build_attestation_payload(None, "soc2", asset_ids=["a1"])

    assert payload["framework"] == {"id": "soc2", "label": "SOC 2"}
    assert payload["summary"]["total_controls"] == 2
    assert payload["summary"]["met_controls"] == 2
    assert payload["summary"]["unmet_controls"] == 0
    assert payload["summary"]["pass_pct"] == 100
    assert payload["summary"]["critical_gaps"] == 0
    assert len(payload["controls"]) == 2
    assert payload["controls"][0]["status"] == "met"
    assert payload["controls"][0]["description"] == "Access controls"
    assert payload["controls"][1]["description"] == ""
    assert "generated_at" in payload


@pytest.mark.asyncio
async def test_payload_classifies_unmet_partial_and_counts_gaps():
    async def _summary(_session, _fw, *, asset_ids):
        return [
            _control(control_id="CC6.1", finding_count=3, sev="critical"),
            _control(control_id="CC6.2", finding_count=1, sev="high"),
            _control(control_id="CC7.1", finding_count=2, sev="medium"),
            _control(control_id="CC8.1", finding_count=0, sev=None),
        ]

    async def _findings(_session, _fw, control_id, *, asset_ids):
        if control_id == "CC6.1":
            return [
                _brief(brief_id=1, severity="critical"),
                _brief(brief_id=2, severity="high"),
            ]
        return []

    async def _controls(_session, _fw):
        return []

    with (
        patch("src.compliance.service.get_framework", side_effect=_resolve_framework),
        patch("src.compliance.service.get_framework_summary", side_effect=_summary),
        patch("src.compliance.service.get_findings_for_control", side_effect=_findings),
        patch("src.compliance.service.list_controls_for_framework", side_effect=_controls),
    ):
        payload = await build_attestation_payload(None, "soc2", asset_ids=["a1"])

    assert payload["summary"]["total_controls"] == 4
    assert payload["summary"]["met_controls"] == 1
    assert payload["summary"]["unmet_controls"] == 2
    assert payload["summary"]["partial_controls"] == 1
    assert payload["summary"]["critical_gaps"] == 1
    assert payload["summary"]["high_gaps"] == 1
    assert payload["summary"]["pass_pct"] == 25
    cc61 = next(c for c in payload["controls"] if c["control_id"] == "CC6.1")
    assert cc61["status"] == "unmet"
    assert len(cc61["findings"]) == 2
    assert cc61["findings"][0]["severity"] == "critical"
    assert cc61["findings"][0]["source_label"] == "semgrep:acme/api"


@pytest.mark.asyncio
async def test_payload_empty_assets_yields_zero_coverage():
    async def _summary(_session, _fw, *, asset_ids):
        return [_control(control_id="CC6.1", finding_count=0, sev=None)]

    async def _findings(_session, _fw, _control_id, *, asset_ids):
        return []

    async def _controls(_session, _fw):
        return [
            FrameworkControl(
                framework="soc2",
                control_id="CC6.1",
                title="Logical access",
                description="",
                category="access",
            )
        ]

    with (
        patch("src.compliance.service.get_framework", side_effect=_resolve_framework),
        patch("src.compliance.service.get_framework_summary", side_effect=_summary),
        patch("src.compliance.service.get_findings_for_control", side_effect=_findings),
        patch("src.compliance.service.list_controls_for_framework", side_effect=_controls),
    ):
        payload = await build_attestation_payload(None, "soc2", asset_ids=[])

    assert payload["summary"]["pass_pct"] == 100
    assert payload["summary"]["total_controls"] == 1
    assert payload["controls"][0]["status"] == "met"
