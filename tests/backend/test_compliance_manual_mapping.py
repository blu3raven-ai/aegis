"""Manually mapping a finding to a control.

Service-level coverage of create / idempotent re-add / suppressed-restore / BOLA
scope, the mappable-findings picker search, and the manual flag surfacing in the
control's findings list. Plus router-level permission + status-code gates.
"""
from __future__ import annotations

import asyncio
import os
import threading
import uuid
from unittest.mock import MagicMock, patch

import pytest

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost:5432/test")
os.environ.setdefault("APP_SECRET", "0" * 64)

from fastapi import FastAPI, Request  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import delete, select  # noqa: E402

from src.compliance import service as svc  # noqa: E402
from src.compliance.models import (  # noqa: E402
    ComplianceControlMapping,
    FindingBrief,
    Framework,
    FrameworkControl,
)
from src.compliance.router import router as compliance_router  # noqa: E402
from src.compliance.service import ControlNotFound, FrameworkNotFound  # noqa: E402
from src.db.models import Asset, Finding  # noqa: E402

CONTROL_ID = "CC6.8"


async def _seed(
    db_session,
    *,
    mapped: bool = False,
    suppressed: bool = False,
    title: str = "Vuln",
    state: str = "open",
):
    """Seed a unique framework + control + asset + one finding.

    Returns (framework_id, asset_id, finding, mapping|None). A unique framework
    id per call keeps tests independent of ordering and of any bundled seed data.
    """
    fw_id = f"tf-{uuid.uuid4().hex[:10]}"
    db_session.add(Framework(id=fw_id, label="Test FW", is_custom=True))
    db_session.add(FrameworkControl(framework=fw_id, control_id=CONTROL_ID, title="Malware"))
    asset_id = str(uuid.uuid4())
    db_session.add(Asset(
        id=asset_id, type="repo", source="source_connection",
        external_ref=f"github:acme-org/{uuid.uuid4().hex}", display_name="acme-org/api",
    ))
    await db_session.flush()
    finding = Finding(
        tool="dependencies_scanning", identity_key=f"k-{uuid.uuid4()}", asset_id=asset_id,
        state=state, severity="high", title=title,
    )
    db_session.add(finding)
    await db_session.flush()
    mapping = None
    if mapped:
        mapping = ComplianceControlMapping(
            finding_id=finding.id, framework=fw_id, control_id=CONTROL_ID,
            confidence=0.9, rationale="auto", suppressed=suppressed,
        )
        db_session.add(mapping)
        await db_session.flush()
    await db_session.commit()
    return fw_id, asset_id, finding, mapping


async def _cleanup(db_session, fw_id, asset_id):
    await db_session.execute(delete(ComplianceControlMapping).where(ComplianceControlMapping.framework == fw_id))
    await db_session.execute(delete(Finding).where(Finding.asset_id == asset_id))
    await db_session.execute(delete(Asset).where(Asset.id == asset_id))
    await db_session.execute(delete(FrameworkControl).where(FrameworkControl.framework == fw_id))
    await db_session.execute(delete(Framework).where(Framework.id == fw_id))
    await db_session.commit()


@pytest.mark.asyncio
async def test_create_manual_mapping_adds_and_counts(db_session):
    fw_id, asset_id, finding, _ = await _seed(db_session)
    try:
        result = await svc.create_manual_mapping(
            db_session, fw_id, CONTROL_ID, finding.id, asset_ids=[asset_id],
        )
        await db_session.commit()
        assert result is not None
        row, created = result
        assert created is True
        assert row.manual is True
        assert row.confidence == 1.0
        assert row.suppressed is False

        # Surfaces in the control's findings list flagged manual, and counts.
        briefs = await svc.get_findings_for_control(db_session, fw_id, CONTROL_ID, asset_ids=[asset_id])
        assert len(briefs) == 1
        assert briefs[0].id == finding.id
        assert briefs[0].manual is True

        summary = await svc.get_framework_summary(db_session, fw_id, asset_ids=[asset_id])
        c = next(x for x in summary if x.control_id == CONTROL_ID)
        assert c.finding_count == 1
    finally:
        await _cleanup(db_session, fw_id, asset_id)


@pytest.mark.asyncio
async def test_create_manual_mapping_is_idempotent(db_session):
    fw_id, asset_id, finding, _ = await _seed(db_session)
    try:
        first = await svc.create_manual_mapping(
            db_session, fw_id, CONTROL_ID, finding.id, asset_ids=[asset_id],
        )
        await db_session.commit()
        assert first is not None and first[1] is True

        second = await svc.create_manual_mapping(
            db_session, fw_id, CONTROL_ID, finding.id, asset_ids=[asset_id],
        )
        await db_session.commit()
        assert second is not None
        row, created = second
        assert created is False
        assert row.id == first[0].id

        # Still exactly one mapping row.
        rows = (await db_session.execute(
            select(ComplianceControlMapping).where(ComplianceControlMapping.framework == fw_id)
        )).scalars().all()
        assert len(rows) == 1
    finally:
        await _cleanup(db_session, fw_id, asset_id)


@pytest.mark.asyncio
async def test_duplicate_mapping_blocked_by_unique_constraint(db_session):
    # The DB-level invariant ON CONFLICT recovery relies on: a finding can map
    # to a given control at most once.
    from sqlalchemy.exc import IntegrityError

    fw_id, asset_id, finding, _ = await _seed(db_session)
    try:
        db_session.add(ComplianceControlMapping(
            finding_id=finding.id, framework=fw_id, control_id=CONTROL_ID, confidence=1.0,
        ))
        await db_session.commit()
        db_session.add(ComplianceControlMapping(
            finding_id=finding.id, framework=fw_id, control_id=CONTROL_ID, confidence=0.5,
        ))
        with pytest.raises(IntegrityError):
            await db_session.flush()
        await db_session.rollback()
    finally:
        await _cleanup(db_session, fw_id, asset_id)


@pytest.mark.asyncio
async def test_create_manual_mapping_restores_suppressed(db_session):
    # A previously auto-mapped + suppressed row should be un-suppressed and
    # re-flagged manual when the analyst re-adds it.
    fw_id, asset_id, finding, mapping = await _seed(db_session, mapped=True, suppressed=True)
    try:
        result = await svc.create_manual_mapping(
            db_session, fw_id, CONTROL_ID, finding.id, asset_ids=[asset_id],
        )
        await db_session.commit()
        assert result is not None
        row, created = result
        assert created is True
        assert row.id == mapping.id
        assert row.suppressed is False
        assert row.manual is True
        # Restoring normalizes the row to a uniform manual mapping.
        assert row.confidence == 1.0
        assert row.rationale == "Mapped manually by an analyst"

        briefs = await svc.get_findings_for_control(db_session, fw_id, CONTROL_ID, asset_ids=[asset_id])
        assert len(briefs) == 1 and briefs[0].suppressed is False
    finally:
        await _cleanup(db_session, fw_id, asset_id)


@pytest.mark.asyncio
async def test_create_manual_mapping_bola_out_of_scope(db_session):
    fw_id, asset_id, finding, _ = await _seed(db_session)
    try:
        # Caller scoped to a different asset can't map this finding.
        result = await svc.create_manual_mapping(
            db_session, fw_id, CONTROL_ID, finding.id, asset_ids=[str(uuid.uuid4())],
        )
        assert result is None
        # Empty scope is also fail-closed.
        assert await svc.create_manual_mapping(
            db_session, fw_id, CONTROL_ID, finding.id, asset_ids=[],
        ) is None
        # No mapping was created.
        rows = (await db_session.execute(
            select(ComplianceControlMapping).where(ComplianceControlMapping.framework == fw_id)
        )).scalars().all()
        assert rows == []
    finally:
        await _cleanup(db_session, fw_id, asset_id)


@pytest.mark.asyncio
async def test_create_manual_mapping_unknown_target_raises(db_session):
    fw_id, asset_id, finding, _ = await _seed(db_session)
    try:
        with pytest.raises(FrameworkNotFound):
            await svc.create_manual_mapping(
                db_session, "no-such-fw", CONTROL_ID, finding.id, asset_ids=[asset_id],
            )
        with pytest.raises(ControlNotFound):
            await svc.create_manual_mapping(
                db_session, fw_id, "NO.SUCH", finding.id, asset_ids=[asset_id],
            )
    finally:
        await _cleanup(db_session, fw_id, asset_id)


@pytest.mark.asyncio
async def test_create_manual_mapping_absent_finding_returns_none(db_session):
    fw_id, asset_id, _finding, _ = await _seed(db_session)
    try:
        assert await svc.create_manual_mapping(
            db_session, fw_id, CONTROL_ID, 999_000_111, asset_ids=[asset_id],
        ) is None
    finally:
        await _cleanup(db_session, fw_id, asset_id)


@pytest.mark.asyncio
async def test_create_manual_mapping_rejects_non_live_finding(db_session):
    # A dismissed finding isn't live evidence — mapping it would create a row
    # that never displays or counts, so it's rejected loudly.
    fw_id, asset_id, finding, _ = await _seed(db_session, state="dismissed")
    try:
        with pytest.raises(ValueError, match="dismissed"):
            await svc.create_manual_mapping(
                db_session, fw_id, CONTROL_ID, finding.id, asset_ids=[asset_id],
            )
    finally:
        await _cleanup(db_session, fw_id, asset_id)


@pytest.mark.asyncio
async def test_create_manual_mapping_allows_deferred_finding(db_session):
    fw_id, asset_id, finding, _ = await _seed(db_session, state="deferred")
    try:
        result = await svc.create_manual_mapping(
            db_session, fw_id, CONTROL_ID, finding.id, asset_ids=[asset_id],
        )
        await db_session.commit()
        assert result is not None and result[1] is True
    finally:
        await _cleanup(db_session, fw_id, asset_id)


@pytest.mark.asyncio
async def test_search_mappable_findings_excludes_mapped_and_filters(db_session):
    # One finding already actively mapped, one open + unmapped with a distinct
    # title — only the unmapped one is a candidate, and q matches its title.
    fw_id, asset_id, mapped_finding, _ = await _seed(db_session, mapped=True, title="Already mapped")
    extra = Finding(
        tool="secret_scanning", identity_key=f"k-{uuid.uuid4()}", asset_id=asset_id,
        state="open", severity="critical", title="Leaked token alpha",
    )
    deferred = Finding(
        tool="iac", identity_key=f"k-{uuid.uuid4()}", asset_id=asset_id,
        state="deferred", severity="low", title="Deferred drift",
    )
    db_session.add_all([extra, deferred])
    await db_session.commit()
    try:
        # No query → returns unmapped open + deferred candidates, not the mapped
        # finding. Critical sorts ahead of low via the severity rank.
        candidates = await svc.search_mappable_findings(
            db_session, fw_id, CONTROL_ID, q=None, asset_ids=[asset_id],
        )
        ids = [c.id for c in candidates]
        assert extra.id in ids
        assert deferred.id in ids
        assert mapped_finding.id not in ids
        assert ids.index(extra.id) < ids.index(deferred.id)

        # Title filter narrows to the matching finding.
        hits = await svc.search_mappable_findings(
            db_session, fw_id, CONTROL_ID, q="alpha", asset_ids=[asset_id],
        )
        assert [h.id for h in hits] == [extra.id]
        assert hits[0].title == "Leaked token alpha"
        assert hits[0].org == "acme-org"

        # Out-of-scope caller sees nothing.
        assert await svc.search_mappable_findings(
            db_session, fw_id, CONTROL_ID, q=None, asset_ids=[str(uuid.uuid4())],
        ) == []
    finally:
        await db_session.execute(delete(Finding).where(Finding.id.in_([extra.id, deferred.id])))
        await _cleanup(db_session, fw_id, asset_id)


# ── Router-level: permission + status codes (run_db mocked) ──────────────────


def _async_return(value):
    async def _fn(*_args, **_kwargs):
        return value
    return _fn


def _run_closure(coro_fn):
    """Execute the router's async _query closure on a fresh loop so service
    exceptions propagate to the handler's try/except (run a dedicated thread
    because the TestClient already holds an asyncio loop on this thread)."""
    box: dict = {}

    def _worker():
        loop = asyncio.new_event_loop()
        try:
            box["value"] = loop.run_until_complete(coro_fn(MagicMock()))
        except BaseException as exc:  # noqa: BLE001
            box["error"] = exc
        finally:
            loop.close()

    t = threading.Thread(target=_worker)
    t.start()
    t.join()
    if "error" in box:
        raise box["error"]
    return box["value"]


def _make_app(*, allow_manage_settings: bool = True, allow_view_findings: bool = True) -> FastAPI:
    from src.authz.enforcement.dependencies import Permission
    from src.authz.permissions.catalog import MANAGE_SETTINGS, VIEW_FINDINGS

    app = FastAPI()
    app.include_router(compliance_router)

    @app.middleware("http")
    async def inject_user(request: Request, call_next):
        request.state.user_sub = "admin@example.com"
        return await call_next(request)

    if allow_manage_settings:
        app.dependency_overrides[Permission(MANAGE_SETTINGS)] = lambda: None
    if allow_view_findings:
        app.dependency_overrides[Permission(VIEW_FINDINGS)] = lambda: None
    return app


def test_post_mapping_requires_manage_settings():
    app = _make_app(allow_manage_settings=False)
    with patch("src.authz.enforcement.dependencies.has_role_permission", return_value=False):
        r = TestClient(app).post(
            "/api/v1/compliance/frameworks/soc2/controls/CC6.8/mappings",
            json={"finding_id": 1},
        )
    assert r.status_code == 403


def test_post_mapping_created_201():
    app = _make_app()
    recorder = MagicMock()
    fake_row = MagicMock()
    fake_row.id = 4242
    with (
        patch("src.compliance.router.resolve_asset_ids_from_request", new=_async_return(["a-1"])),
        patch("src.compliance.router.run_db", return_value=(fake_row, True)),
        patch("src.compliance.router.get_recorder", return_value=recorder),
    ):
        r = TestClient(app).post(
            "/api/v1/compliance/frameworks/soc2/controls/CC6.8/mappings",
            json={"finding_id": 7},
        )
    assert r.status_code == 201, r.text
    body = r.json()
    assert body == {"mapping_id": 4242, "finding_id": 7, "created": True}
    recorder.record.assert_called_once()
    assert recorder.record.call_args.kwargs["action"] == "compliance.mapping_added"


def test_post_mapping_idempotent_skips_audit():
    app = _make_app()
    recorder = MagicMock()
    fake_row = MagicMock()
    fake_row.id = 11
    with (
        patch("src.compliance.router.resolve_asset_ids_from_request", new=_async_return(["a-1"])),
        patch("src.compliance.router.run_db", return_value=(fake_row, False)),
        patch("src.compliance.router.get_recorder", return_value=recorder),
    ):
        r = TestClient(app).post(
            "/api/v1/compliance/frameworks/soc2/controls/CC6.8/mappings",
            json={"finding_id": 7},
        )
    assert r.status_code == 201, r.text
    assert r.json()["created"] is False
    recorder.record.assert_not_called()


def test_post_mapping_out_of_scope_finding_404():
    app = _make_app()
    with (
        patch("src.compliance.router.resolve_asset_ids_from_request", new=_async_return(["a-1"])),
        patch("src.compliance.router.run_db", return_value=None),
    ):
        r = TestClient(app).post(
            "/api/v1/compliance/frameworks/soc2/controls/CC6.8/mappings",
            json={"finding_id": 7},
        )
    assert r.status_code == 404


def test_post_mapping_non_live_finding_422():
    app = _make_app()
    with (
        patch("src.compliance.router.resolve_asset_ids_from_request", new=_async_return(["a-1"])),
        patch(
            "src.compliance.router.create_manual_mapping",
            side_effect=ValueError("finding 7 is dismissed; only open or deferred findings can be mapped"),
        ),
        patch("src.compliance.router.run_db", new=lambda fn: _run_closure(fn)),
    ):
        r = TestClient(app).post(
            "/api/v1/compliance/frameworks/soc2/controls/CC6.8/mappings",
            json={"finding_id": 7},
        )
    assert r.status_code == 422
    assert "dismissed" in r.json()["detail"]


def test_control_findings_response_surfaces_manual():
    # Guards the FindingBrief → response mapping: a manual mapping must reach
    # the client as manual=true (else the UI shows a misleading "100% match").
    app = _make_app()
    brief = FindingBrief(
        id=1, tool="dependencies_scanning", org="acme-org", repo="api",
        severity="high", state="open", identity_key="k", confidence=1.0,
        rationale="Mapped manually by an analyst", mapping_id=9,
        suppressed=False, manual=True,
    )
    with (
        patch("src.compliance.router.resolve_asset_ids_from_request", new=_async_return(["a-1"])),
        patch("src.compliance.router.run_db", return_value=[brief]),
    ):
        r = TestClient(app).get(
            "/api/v1/compliance/frameworks/soc2/controls/CC6.8/findings",
        )
    assert r.status_code == 200, r.text
    findings = r.json()["findings"]
    assert findings[0]["manual"] is True
