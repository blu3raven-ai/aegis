"""Tests for the compliance read endpoints under /api/v1/compliance.

Covers the 5 GET handlers migrated from GraphQL:

  - GET /frameworks
  - GET /frameworks/{framework}/controls
  - GET /frameworks/{framework}/summary
  - GET /frameworks/{framework}/controls/{control_id}/findings
  - GET /findings/{finding_id}/controls

The cross-scope test on /findings/{finding_id}/controls is the keystone for
the security hardening — without ``asset_ids`` filtering on the service the
handler would leak control mappings for findings outside the caller's scope.
"""
from __future__ import annotations

import asyncio
import os
import threading
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost:5432/test")
os.environ.setdefault("RUNNER_ENCRYPTION_KEY", "0" * 64)

from fastapi import FastAPI, Request  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from src.authz.enforcement.dependencies import Permission  # noqa: E402
from src.authz.permissions.catalog import VIEW_FINDINGS  # noqa: E402
from src.compliance.models import (  # noqa: E402
    ControlSummaryItem,
    FindingBrief,
    Framework,
    FrameworkControl,
)
from src.compliance.router import router as compliance_router  # noqa: E402


_VIEWER_PERMS = {"view_findings"}
_NO_PERMS: set[str] = set()


def _make_app(*, allow_view_findings: bool = True) -> FastAPI:
    app = FastAPI()
    app.include_router(compliance_router)

    @app.middleware("http")
    async def inject_user(request: Request, call_next):
        request.state.user_sub = "viewer-1"
        request.state.user_role = "viewer"
        request.state.user_role_id = None
        return await call_next(request)

    if allow_view_findings:
        app.dependency_overrides[Permission(VIEW_FINDINGS)] = lambda: None
    return app


def _run_closure(coro_fn):
    """Patches in for run_db so the router's inner ``_query`` runs against a
    MagicMock session on a fresh loop. Mirrors the pattern in
    ``test_compliance_crud.py`` — the FastAPI test client already owns the
    main thread's loop, so nested asyncio.run() would deadlock."""
    result_box: dict = {}
    error_box: dict = {}

    def _worker():
        loop = asyncio.new_event_loop()
        try:
            result_box["value"] = loop.run_until_complete(coro_fn(MagicMock()))
        except BaseException as exc:
            error_box["error"] = exc
        finally:
            loop.close()

    t = threading.Thread(target=_worker)
    t.start()
    t.join()
    if "error" in error_box:
        raise error_box["error"]
    return result_box["value"]


def _fw(framework_id: str = "soc2", label: str = "SOC 2") -> Framework:
    return Framework(
        id=framework_id,
        label=label,
        description=None,
        is_custom=False,
        created_by_user_id=None,
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )


def _ctrl(
    *,
    framework_id: str = "soc2",
    control_id: str = "CC6.1",
    title: str = "Logical access controls",
) -> FrameworkControl:
    return FrameworkControl(
        id=1,
        framework=framework_id,
        control_id=control_id,
        title=title,
        description="desc",
        category="Access",
        is_custom=False,
        created_by_user_id=None,
        created_at=datetime.now(timezone.utc),
    )


def _summary_item(**overrides) -> ControlSummaryItem:
    base = {
        "framework": "soc2",
        "control_id": "CC6.1",
        "title": "Logical access controls",
        "category": "Access",
        "finding_count": 3,
        "highest_severity": "high",
    }
    base.update(overrides)
    return ControlSummaryItem(**base)


def _brief(**overrides) -> FindingBrief:
    base = {
        "id": 1,
        "tool": "trivy",
        "org": "acme-org",
        "repo": "repo-1",
        "severity": "high",
        "state": "open",
        "identity_key": "k-1",
        "confidence": 0.9,
        "rationale": "matched",
        "mapping_id": 1,
    }
    base.update(overrides)
    return FindingBrief(**base)


# ── GET /frameworks ────────────────────────────────────────────────────────


def test_list_frameworks_returns_envelope_with_rows():
    rows = [
        {"id": "soc2", "label": "SOC 2"},
        {"id": "iso27001", "label": "ISO 27001"},
    ]
    with (
        patch("src.compliance.router.run_db", side_effect=_run_closure),
        patch("src.compliance.router.list_frameworks", new=AsyncMock(return_value=rows)) as mock_svc,
    ):
        resp = TestClient(_make_app()).get("/api/v1/compliance/frameworks")

    assert resp.status_code == 200
    assert resp.json() == {"frameworks": rows}
    mock_svc.assert_awaited_once()


def test_list_frameworks_forbidden_without_view_findings():
    with (
        patch("src.authz.enforcement.dependencies.has_role_permission", return_value=False),
        patch("src.compliance.router.list_frameworks", new=AsyncMock()) as mock_svc,
    ):
        resp = TestClient(_make_app(allow_view_findings=False)).get("/api/v1/compliance/frameworks")

    assert resp.status_code == 403
    mock_svc.assert_not_called()


# ── GET /frameworks/{framework}/controls ──────────────────────────────────


def test_list_framework_controls_returns_envelope():
    with (
        patch("src.compliance.router.run_db", side_effect=_run_closure),
        patch("src.compliance.router.get_framework", new=AsyncMock(return_value=_fw())),
        patch(
            "src.compliance.router.list_controls_for_framework",
            new=AsyncMock(return_value=[_ctrl()]),
        ) as mock_svc,
    ):
        resp = TestClient(_make_app()).get("/api/v1/compliance/frameworks/soc2/controls")

    assert resp.status_code == 200
    body = resp.json()
    assert list(body.keys()) == ["controls"]
    assert len(body["controls"]) == 1
    assert body["controls"][0]["framework"] == "soc2"
    assert body["controls"][0]["control_id"] == "CC6.1"
    assert body["controls"][0]["title"] == "Logical access controls"
    mock_svc.assert_awaited_once()


def test_list_framework_controls_unknown_framework_404():
    with (
        patch("src.compliance.router.run_db", side_effect=_run_closure),
        patch("src.compliance.router.get_framework", new=AsyncMock(return_value=None)),
        patch(
            "src.compliance.router.list_controls_for_framework",
            new=AsyncMock(),
        ) as mock_svc,
    ):
        resp = TestClient(_make_app()).get("/api/v1/compliance/frameworks/madeup/controls")

    assert resp.status_code == 404
    assert resp.json()["detail"] == "Unknown framework: madeup"
    mock_svc.assert_not_called()


def test_list_framework_controls_forbidden_without_view_findings():
    with (
        patch("src.authz.enforcement.dependencies.has_role_permission", return_value=False),
        patch(
            "src.compliance.router.list_controls_for_framework",
            new=AsyncMock(),
        ) as mock_svc,
    ):
        resp = TestClient(_make_app(allow_view_findings=False)).get("/api/v1/compliance/frameworks/soc2/controls")

    assert resp.status_code == 403
    mock_svc.assert_not_called()


# ── GET /frameworks/{framework}/summary ───────────────────────────────────


def test_get_framework_summary_returns_envelope_for_scoped_caller():
    captured: dict = {}

    async def _fake_summary(_session, framework, *, asset_ids):
        captured["framework"] = framework
        captured["asset_ids"] = asset_ids
        return [_summary_item()]

    with (
        patch(
            "src.compliance.router.resolve_asset_ids_from_request",
            new=AsyncMock(return_value=["asset-1", "asset-2"]),
        ),
        patch("src.compliance.router.run_db", side_effect=_run_closure),
        patch("src.compliance.router.get_framework", new=AsyncMock(return_value=_fw())),
        patch("src.compliance.router.get_framework_summary", side_effect=_fake_summary),
    ):
        resp = TestClient(_make_app()).get("/api/v1/compliance/frameworks/soc2/summary")

    assert resp.status_code == 200
    body = resp.json()
    assert body["framework"] == "soc2"
    assert body["label"] == "SOC 2"
    assert len(body["controls"]) == 1
    assert body["controls"][0]["finding_count"] == 3
    assert body["controls"][0]["highest_severity"] == "high"
    assert captured["framework"] == "soc2"
    assert captured["asset_ids"] == ["asset-1", "asset-2"]


def test_get_framework_summary_empty_scope_returns_zero_count_controls():
    """Empty asset_ids must yield reference controls with zero counts, not
    a 4xx — matches the existing semantics tested at the service layer."""

    async def _fake_summary(_session, _framework, *, asset_ids):
        assert asset_ids == []
        return [_summary_item(finding_count=0, highest_severity=None)]

    with (
        patch(
            "src.compliance.router.resolve_asset_ids_from_request",
            new=AsyncMock(return_value=[]),
        ),
        patch("src.compliance.router.run_db", side_effect=_run_closure),
        patch("src.compliance.router.get_framework", new=AsyncMock(return_value=_fw())),
        patch("src.compliance.router.get_framework_summary", side_effect=_fake_summary),
    ):
        resp = TestClient(_make_app()).get("/api/v1/compliance/frameworks/soc2/summary")

    assert resp.status_code == 200
    body = resp.json()
    assert body["controls"][0]["finding_count"] == 0
    assert body["controls"][0]["highest_severity"] is None


def test_get_framework_summary_unknown_framework_404():
    with (
        patch(
            "src.compliance.router.resolve_asset_ids_from_request",
            new=AsyncMock(return_value=["asset-1"]),
        ),
        patch("src.compliance.router.run_db", side_effect=_run_closure),
        patch("src.compliance.router.get_framework", new=AsyncMock(return_value=None)),
        patch(
            "src.compliance.router.get_framework_summary",
            new=AsyncMock(),
        ) as mock_svc,
    ):
        resp = TestClient(_make_app()).get("/api/v1/compliance/frameworks/madeup/summary")

    assert resp.status_code == 404
    assert resp.json()["detail"] == "Unknown framework: madeup"
    mock_svc.assert_not_called()


def test_get_framework_summary_forbidden_without_view_findings():
    with (
        patch("src.authz.enforcement.dependencies.has_role_permission", return_value=False),
        patch(
            "src.compliance.router.get_framework_summary",
            new=AsyncMock(),
        ) as mock_svc,
    ):
        resp = TestClient(_make_app(allow_view_findings=False)).get("/api/v1/compliance/frameworks/soc2/summary")

    assert resp.status_code == 403
    mock_svc.assert_not_called()


# ── GET /frameworks/{framework}/controls/{control_id}/findings ────────────


def test_get_control_findings_returns_envelope_for_scoped_caller():
    captured: dict = {}

    async def _fake_findings(_session, framework, control_id, *, asset_ids, include_suppressed=False):
        captured["framework"] = framework
        captured["control_id"] = control_id
        captured["asset_ids"] = asset_ids
        return [_brief(id=42, identity_key="k-42", rationale="why")]

    with (
        patch(
            "src.compliance.router.resolve_asset_ids_from_request",
            new=AsyncMock(return_value=["asset-1"]),
        ),
        patch("src.compliance.router.run_db", side_effect=_run_closure),
        patch("src.compliance.router.get_framework", new=AsyncMock(return_value=_fw())),
        patch("src.compliance.router.get_findings_for_control", side_effect=_fake_findings),
    ):
        resp = TestClient(_make_app()).get(
            "/api/v1/compliance/frameworks/soc2/controls/CC6.1/findings",
        )

    assert resp.status_code == 200
    body = resp.json()
    assert body["framework"] == "soc2"
    assert body["control_id"] == "CC6.1"
    assert len(body["findings"]) == 1
    finding = body["findings"][0]
    assert finding["id"] == 42
    assert finding["tool"] == "trivy"
    assert finding["identity_key"] == "k-42"
    assert finding["rationale"] == "why"
    assert captured["asset_ids"] == ["asset-1"]


def test_get_control_findings_empty_scope_returns_empty_list():
    with (
        patch(
            "src.compliance.router.resolve_asset_ids_from_request",
            new=AsyncMock(return_value=[]),
        ),
        patch("src.compliance.router.run_db", side_effect=_run_closure),
        patch("src.compliance.router.get_framework", new=AsyncMock(return_value=_fw())),
        patch(
            "src.compliance.router.get_findings_for_control",
            new=AsyncMock(return_value=[]),
        ),
    ):
        resp = TestClient(_make_app()).get(
            "/api/v1/compliance/frameworks/soc2/controls/CC6.1/findings",
        )

    assert resp.status_code == 200
    assert resp.json() == {"framework": "soc2", "control_id": "CC6.1", "findings": []}


def test_get_control_findings_unknown_framework_404():
    with (
        patch(
            "src.compliance.router.resolve_asset_ids_from_request",
            new=AsyncMock(return_value=["asset-1"]),
        ),
        patch("src.compliance.router.run_db", side_effect=_run_closure),
        patch("src.compliance.router.get_framework", new=AsyncMock(return_value=None)),
        patch(
            "src.compliance.router.get_findings_for_control",
            new=AsyncMock(),
        ) as mock_svc,
    ):
        resp = TestClient(_make_app()).get(
            "/api/v1/compliance/frameworks/madeup/controls/CC6.1/findings",
        )

    assert resp.status_code == 404
    assert resp.json()["detail"] == "Unknown framework: madeup"
    mock_svc.assert_not_called()


def test_get_control_findings_forbidden_without_view_findings():
    with (
        patch("src.authz.enforcement.dependencies.has_role_permission", return_value=False),
        patch(
            "src.compliance.router.get_findings_for_control",
            new=AsyncMock(),
        ) as mock_svc,
    ):
        resp = TestClient(_make_app(allow_view_findings=False)).get(
            "/api/v1/compliance/frameworks/soc2/controls/CC6.1/findings",
        )

    assert resp.status_code == 403
    mock_svc.assert_not_called()


# ── GET /findings/{finding_id}/controls ───────────────────────────────────


def test_get_finding_controls_returns_envelope_for_finding_in_scope():
    captured: dict = {}

    async def _fake_controls(_session, finding_id, *, asset_ids):
        captured["finding_id"] = finding_id
        captured["asset_ids"] = asset_ids
        return [
            {
                "mapping_id": 1,
                "framework": "soc2",
                "control_id": "CC6.1",
                "confidence": 0.85,
                "rationale": "access control",
                "title": "Logical access controls",
                "category": "Access",
                "created_at": "2026-01-01T00:00:00+00:00",
            },
        ]

    with (
        patch(
            "src.compliance.router.resolve_asset_ids_from_request",
            new=AsyncMock(return_value=["asset-A"]),
        ),
        patch("src.compliance.router.run_db", side_effect=_run_closure),
        patch("src.compliance.router.get_controls_for_finding", side_effect=_fake_controls),
    ):
        resp = TestClient(_make_app()).get("/api/v1/compliance/findings/42/controls")

    assert resp.status_code == 200
    body = resp.json()
    assert body["finding_id"] == 42
    assert len(body["mappings"]) == 1
    mapping = body["mappings"][0]
    assert mapping["framework"] == "soc2"
    assert mapping["control_id"] == "CC6.1"
    assert mapping["title"] == "Logical access controls"
    assert mapping["confidence"] == 0.85
    assert mapping["rationale"] == "access control"
    assert captured["finding_id"] == 42
    assert captured["asset_ids"] == ["asset-A"]


def test_get_finding_controls_empty_scope_returns_empty_mappings():
    """No accessible assets means no mappings — empty list, not a 403."""
    captured: dict = {}

    async def _fake_controls(_session, finding_id, *, asset_ids):
        captured["asset_ids"] = asset_ids
        # Service returns [] when asset_ids is empty — assert here too.
        assert asset_ids == []
        return []

    with (
        patch(
            "src.compliance.router.resolve_asset_ids_from_request",
            new=AsyncMock(return_value=[]),
        ),
        patch("src.compliance.router.run_db", side_effect=_run_closure),
        patch("src.compliance.router.get_controls_for_finding", side_effect=_fake_controls),
    ):
        resp = TestClient(_make_app()).get("/api/v1/compliance/findings/42/controls")

    assert resp.status_code == 200
    assert resp.json() == {"finding_id": 42, "mappings": []}
    assert captured["asset_ids"] == []


def test_get_finding_controls_cross_scope_request_returns_empty_mappings():
    """Security keystone: a caller scoped to asset B asking about a finding
    owned by asset A must get an empty mapping list, not the finding's
    control mappings. Without the asset_ids filter on
    ``get_controls_for_finding`` this would leak control labels and tied
    framework identifiers cross-scope.
    """
    seen_args: dict = {}

    async def _fake_controls(_session, finding_id, *, asset_ids):
        # The handler passes the caller's scope to the service. The service is
        # responsible for restricting the SQL join through ``Finding.asset_id
        # IN (asset_ids)`` — a finding owned by asset-A will not survive the
        # ``IN (asset-B)`` filter and the call returns [].
        seen_args["finding_id"] = finding_id
        seen_args["asset_ids"] = asset_ids
        return []

    with (
        patch(
            "src.compliance.router.resolve_asset_ids_from_request",
            new=AsyncMock(return_value=["asset-B"]),
        ),
        patch("src.compliance.router.run_db", side_effect=_run_closure),
        patch("src.compliance.router.get_controls_for_finding", side_effect=_fake_controls),
    ):
        resp = TestClient(_make_app()).get("/api/v1/compliance/findings/42/controls")

    assert resp.status_code == 200
    assert resp.json() == {"finding_id": 42, "mappings": []}
    # The handler MUST forward the caller's scope so the service can apply the
    # asset-id filter; if this assertion ever fails the security gap is back.
    assert seen_args["asset_ids"] == ["asset-B"]
    assert seen_args["finding_id"] == 42


def test_get_finding_controls_forbidden_without_view_findings():
    with (
        patch("src.authz.enforcement.dependencies.has_role_permission", return_value=False),
        patch(
            "src.compliance.router.get_controls_for_finding",
            new=AsyncMock(),
        ) as mock_svc,
    ):
        resp = TestClient(_make_app(allow_view_findings=False)).get("/api/v1/compliance/findings/42/controls")

    assert resp.status_code == 403
    mock_svc.assert_not_called()


# ── service-level proof that the scope filter actually fires ──────────────


def test_service_get_controls_for_finding_empty_scope_returns_empty():
    """Service-side fail-closed: empty asset_ids must short-circuit before any
    SQL is issued. Without this gate the service would issue an unscoped
    query and leak cross-scope rows."""
    from src.compliance.service import get_controls_for_finding

    session = MagicMock()
    session.execute = AsyncMock()

    result = asyncio.run(
        get_controls_for_finding(session, finding_id=42, asset_ids=[]),
    )

    assert result == []
    session.execute.assert_not_called()


def test_service_get_controls_for_finding_filters_sql_by_asset_ids():
    """Service-side proof of the security fix: the constructed SQL must join
    through ``Finding`` and constrain ``Finding.asset_id IN (asset_ids)``. We
    inspect the compiled statement directly because a real-DB seed test for a
    single SQL-shape assertion is heavier than the signal warrants."""
    from src.compliance.service import get_controls_for_finding
    from src.db.models import Finding

    captured: dict = {}

    class _FakeResult:
        def all(self):
            return []

    async def _execute(stmt):
        captured["stmt"] = stmt
        return _FakeResult()

    session = MagicMock()
    session.execute = _execute

    result = asyncio.run(
        get_controls_for_finding(
            session, finding_id=42, asset_ids=["assetA", "assetB"],
        ),
    )

    assert result == []
    stmt = captured["stmt"]
    compiled = str(stmt.compile(compile_kwargs={"literal_binds": True}))
    # The join through Finding + the IN filter on Finding.asset_id are the
    # security-critical pieces; assert both appear in the compiled SQL.
    assert Finding.__tablename__ in compiled
    assert "asset_id IN" in compiled
    assert "'assetA'" in compiled
    assert "'assetB'" in compiled
