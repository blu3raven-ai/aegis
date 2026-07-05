"""Tests for Phase 10 correlation rules and hot-reload.

Uses real testcontainers Postgres + Redis (shared session fixtures from conftest).
All org names use 'acme-org'; CVE IDs use fake identifiers with no real advisory.
"""
from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import redis as redis_lib
from testcontainers.redis import RedisContainer

from src.argus.connector import NullArgusConnector
from src.correlation.chain_graph_store import ChainGraphStore
from src.correlation.emit_interface import EmitInterface
from src.correlation.engine import CorrelationEngine
from src.correlation.rule import RuleContext
from src.correlation.rule_pack_loader import RulePack, RulePackLoader
from src.correlation.rules import register_builtin_rules
from src.correlation.rules.container_base_image_propagation import ContainerBaseImagePropagationRule
from src.correlation.rules.credential_reuse_chain import CredentialReuseChainRule
from src.correlation.rules.cross_repo_cve_cluster import CrossRepoCveClusterRule
from src.correlation.rules.public_exposure_data_handling import PublicExposureDataHandlingRule
from src.correlation.state import CorrelationState
from src.db.helpers import run_db
from src.db.models import Chain, ChainEdge, Finding, VerifiedSecret
from sqlalchemy import delete, select

ORG = "acme-org"
REPO_A = "acme-org/service-alpha"
REPO_B = "acme-org/service-beta"
REPO_C = "acme-org/service-gamma"


# ── fixtures ──────────────────────────────────────────────────────────────────


@pytest.fixture(scope="module")
def redis_container():
    with RedisContainer("redis:7-alpine") as rc:
        yield rc


@pytest.fixture
def redis_client(redis_container):
    host = redis_container.get_container_host_ip()
    port = redis_container.get_exposed_port(6379)
    client = redis_lib.Redis(host=host, port=int(port))
    client.flushdb()
    return client


@pytest.fixture(autouse=True)
def _clean():
    async def _del(session):
        await session.execute(delete(ChainEdge))
        await session.execute(delete(Chain))
        await session.execute(delete(Finding).where(Finding.org == ORG))
        await session.execute(delete(VerifiedSecret))
    run_db(_del)
    yield


def _stream_cfg(container) -> dict:
    host = container.get_container_host_ip()
    port = container.get_exposed_port(6379)
    return {"url": f"redis://{host}:{port}", "stream_prefix": "test.p10.", "max_len": 100}


def _redis_cfg(container) -> dict:
    host = container.get_container_host_ip()
    port = container.get_exposed_port(6379)
    return {"url": f"redis://{host}:{port}"}


def _make_ctx(redis_client) -> RuleContext:
    store = ChainGraphStore()
    return RuleContext(
        state=CorrelationState(),
        argus=NullArgusConnector(),
        emit=EmitInterface(redis_client=redis_client, chain_store=store),
    )


def _insert_finding(**kwargs) -> int:
    defaults = {
        "tool": "code_scanning",
        "org": ORG,
        "repo": REPO_A,
        "identity_key": "default-key",
        "state": "open",
        "severity": "medium",
        "detail": {},
    }
    defaults.update(kwargs)

    async def _ins(session):
        f = Finding(**defaults)
        session.add(f)
        await session.flush()
        return f.id

    return run_db(_ins)


def _insert_verified_secret(secret_hash: str, status: str = "verified") -> None:
    from datetime import datetime, timezone, timedelta

    async def _ins(session):
        vs = VerifiedSecret(
            detector_id=f"test-detector-{secret_hash[:8]}",
            secret_hash=secret_hash,
            verified_at=datetime.now(timezone.utc),
            status=status,
            ttl_until=datetime.now(timezone.utc) + timedelta(hours=1),
        )
        session.add(vs)

    run_db(_ins)


def _raw_event(event_type: str, event_id: str = "EVT001", **payload) -> dict:
    return {
        "_stream_id": "1-0",
        "event_id": event_id,
        "event_type": event_type,
        "org_id": ORG,
        "source_component": "test",
        "timestamp_utc": "2026-05-31T00:00:00+00:00",
        "payload": payload,
    }


def _count_chains() -> int:
    async def _q(session):
        result = await session.execute(select(Chain))
        return len(result.scalars().all())

    return run_db(_q)


def _count_edges() -> int:
    async def _q(session):
        result = await session.execute(select(ChainEdge))
        return len(result.scalars().all())

    return run_db(_q)


def _get_edges() -> list[dict]:
    async def _q(session):
        result = await session.execute(select(ChainEdge))
        rows = result.scalars().all()
        return [{"confidence": r.confidence, "edge_type": r.edge_type} for r in rows]

    return run_db(_q)


# ── Rule 6: PublicExposureDataHandling ────────────────────────────────────────


@patch("src.correlation.emit_interface.get_event_publisher")
def test_public_exposure_emits_chain_when_both_markers_present(mock_pub, redis_client):
    mock_pub.return_value.__class__ = type("P", (), {"publish": lambda s, e: None})()

    pub_id = _insert_finding(
        identity_key="pub-1",
        detail={"is_public_facing": True},
    )
    _insert_finding(
        identity_key="sens-1",
        detail={"handles_sensitive_data": True},
    )

    ctx = _make_ctx(redis_client)
    rule = PublicExposureDataHandlingRule()
    rule.evaluate(
        _raw_event(
            "scan.finding",
            finding={
                "id": pub_id,
                "tool": "code_scanning",
                "org": ORG,
                "repo": REPO_A,
                "detail": {"is_public_facing": True},
            },
        ),
        ctx,
    )

    assert _count_chains() == 1
    edges = _get_edges()
    assert len(edges) == 1
    assert abs(edges[0]["confidence"] - 0.85) < 0.001


@patch("src.correlation.emit_interface.get_event_publisher")
def test_public_exposure_no_emit_when_only_public_marker(mock_pub, redis_client):
    mock_pub.return_value.__class__ = type("P", (), {"publish": lambda s, e: None})()

    pub_id = _insert_finding(
        identity_key="pub-only",
        detail={"is_public_facing": True},
    )

    ctx = _make_ctx(redis_client)
    rule = PublicExposureDataHandlingRule()
    rule.evaluate(
        _raw_event(
            "scan.finding",
            finding={
                "id": pub_id,
                "tool": "code_scanning",
                "org": ORG,
                "repo": REPO_A,
                "detail": {"is_public_facing": True},
            },
        ),
        ctx,
    )

    assert _count_chains() == 0


@patch("src.correlation.emit_interface.get_event_publisher")
def test_public_exposure_no_emit_for_non_sast_findings(mock_pub, redis_client):
    mock_pub.return_value.__class__ = type("P", (), {"publish": lambda s, e: None})()

    dep_id = _insert_finding(
        identity_key="dep-marker",
        tool="dependencies",
        detail={"is_public_facing": True},
    )

    ctx = _make_ctx(redis_client)
    rule = PublicExposureDataHandlingRule()
    rule.evaluate(
        _raw_event(
            "scan.finding",
            finding={
                "id": dep_id,
                "tool": "dependencies",
                "org": ORG,
                "repo": REPO_A,
                "detail": {"is_public_facing": True},
            },
        ),
        ctx,
    )

    assert _count_chains() == 0


@patch("src.correlation.emit_interface.get_event_publisher")
def test_public_exposure_idempotent(mock_pub, redis_client):
    mock_pub.return_value.__class__ = type("P", (), {"publish": lambda s, e: None})()

    pub_id = _insert_finding(identity_key="pub-idem", detail={"is_public_facing": True})
    _insert_finding(identity_key="sens-idem", detail={"handles_sensitive_data": True})

    ctx = _make_ctx(redis_client)
    rule = PublicExposureDataHandlingRule()
    event = _raw_event(
        "scan.finding",
        event_id="idem-evt-pub",
        finding={
            "id": pub_id,
            "tool": "code_scanning",
            "org": ORG,
            "repo": REPO_A,
            "detail": {"is_public_facing": True},
        },
    )
    rule.evaluate(event, ctx)
    rule.evaluate(event, ctx)  # replay

    assert _count_chains() == 1
    assert _count_edges() == 1


# ── Rule 7: CrossRepoCveCluster ───────────────────────────────────────────────


@patch("src.correlation.emit_interface.get_event_publisher")
def test_cve_cluster_emits_when_threshold_reached(mock_pub, redis_client):
    mock_pub.return_value.__class__ = type("P", (), {"publish": lambda s, e: None})()

    CVE = "CVE-2025-TESTCLU"
    ids = []
    for i, repo in enumerate([REPO_A, REPO_B, REPO_C]):
        fid = _insert_finding(
            identity_key=f"cve-cluster-{i}",
            tool="dependencies",
            repo=repo,
            detail={"cve_id": CVE},
        )
        ids.append(fid)

    ctx = _make_ctx(redis_client)
    rule = CrossRepoCveClusterRule()
    rule.evaluate(
        _raw_event(
            "scan.finding",
            finding={
                "id": ids[2],
                "tool": "dependencies",
                "org": ORG,
                "repo": REPO_C,
                "detail": {"cve_id": CVE},
            },
        ),
        ctx,
    )

    assert _count_chains() == 1
    assert _count_edges() >= 1
    edges = _get_edges()
    for e in edges:
        assert abs(e["confidence"] - 0.7) < 0.001


@patch("src.correlation.emit_interface.get_event_publisher")
def test_cve_cluster_no_emit_below_threshold(mock_pub, redis_client):
    mock_pub.return_value.__class__ = type("P", (), {"publish": lambda s, e: None})()

    CVE = "CVE-2025-TESTCLU2"
    fid_a = _insert_finding(identity_key="clu-a", tool="dependencies", repo=REPO_A, detail={"cve_id": CVE})
    fid_b = _insert_finding(identity_key="clu-b", tool="dependencies", repo=REPO_B, detail={"cve_id": CVE})

    ctx = _make_ctx(redis_client)
    rule = CrossRepoCveClusterRule()
    rule.evaluate(
        _raw_event(
            "scan.finding",
            finding={
                "id": fid_b,
                "tool": "dependencies",
                "org": ORG,
                "repo": REPO_B,
                "detail": {"cve_id": CVE},
            },
        ),
        ctx,
    )

    # 2 repos < default threshold of 3
    assert _count_chains() == 0


@patch("src.correlation.emit_interface.get_event_publisher")
def test_cve_cluster_idempotent(mock_pub, redis_client):
    mock_pub.return_value.__class__ = type("P", (), {"publish": lambda s, e: None})()

    CVE = "CVE-2025-IDEM"
    ids = []
    for i, repo in enumerate([REPO_A, REPO_B, REPO_C]):
        fid = _insert_finding(
            identity_key=f"cvu-idem-{i}",
            tool="dependencies",
            repo=repo,
            detail={"cve_id": CVE},
        )
        ids.append(fid)

    ctx = _make_ctx(redis_client)
    rule = CrossRepoCveClusterRule()
    event = _raw_event(
        "scan.finding",
        finding={"id": ids[2], "tool": "dependencies", "org": ORG, "repo": REPO_C, "detail": {"cve_id": CVE}},
    )
    rule.evaluate(event, ctx)
    rule.evaluate(event, ctx)

    assert _count_chains() == 1


# ── Rule 8: ContainerBaseImagePropagation ─────────────────────────────────────


@patch("src.correlation.emit_interface.get_event_publisher")
def test_base_image_propagation_emits_when_siblings_share_digest(mock_pub, redis_client):
    mock_pub.return_value.__class__ = type("P", (), {"publish": lambda s, e: None})()

    DIGEST = "sha256:deadbeef00000001"
    base_id = _insert_finding(
        identity_key="base-vuln",
        tool="container_scanning",
        repo=REPO_A,
        detail={"affected_layer": "base", "base_image_digest": DIGEST},
    )
    sibling_id = _insert_finding(
        identity_key="sib-1",
        tool="container_scanning",
        repo=REPO_B,
        detail={"base_image_digest": DIGEST},
    )

    ctx = _make_ctx(redis_client)
    rule = ContainerBaseImagePropagationRule()
    rule.evaluate(
        _raw_event(
            "scan.finding",
            finding={
                "id": base_id,
                "tool": "container_scanning",
                "org": ORG,
                "repo": REPO_A,
                "detail": {"affected_layer": "base", "base_image_digest": DIGEST},
            },
        ),
        ctx,
    )

    assert _count_chains() == 1
    edges = _get_edges()
    assert len(edges) == 1
    assert abs(edges[0]["confidence"] - 0.9) < 0.001
    assert edges[0]["edge_type"] == "base_image_vuln_inherited_by_container"


@patch("src.correlation.emit_interface.get_event_publisher")
def test_base_image_no_emit_when_not_base_layer(mock_pub, redis_client):
    mock_pub.return_value.__class__ = type("P", (), {"publish": lambda s, e: None})()

    DIGEST = "sha256:deadbeef00000002"
    fid = _insert_finding(
        identity_key="app-layer",
        tool="container_scanning",
        detail={"affected_layer": "app", "base_image_digest": DIGEST},
    )
    _insert_finding(
        identity_key="sib-2",
        tool="container_scanning",
        repo=REPO_B,
        detail={"base_image_digest": DIGEST},
    )

    ctx = _make_ctx(redis_client)
    rule = ContainerBaseImagePropagationRule()
    rule.evaluate(
        _raw_event(
            "scan.finding",
            finding={
                "id": fid,
                "tool": "container_scanning",
                "org": ORG,
                "detail": {"affected_layer": "app", "base_image_digest": DIGEST},
            },
        ),
        ctx,
    )

    assert _count_chains() == 0


@patch("src.correlation.emit_interface.get_event_publisher")
def test_base_image_no_emit_when_no_siblings(mock_pub, redis_client):
    mock_pub.return_value.__class__ = type("P", (), {"publish": lambda s, e: None})()

    DIGEST = "sha256:unique0000000003"
    fid = _insert_finding(
        identity_key="lone-base",
        tool="container_scanning",
        detail={"affected_layer": "base", "base_image_digest": DIGEST},
    )

    ctx = _make_ctx(redis_client)
    rule = ContainerBaseImagePropagationRule()
    rule.evaluate(
        _raw_event(
            "scan.finding",
            finding={
                "id": fid,
                "tool": "container_scanning",
                "org": ORG,
                "detail": {"affected_layer": "base", "base_image_digest": DIGEST},
            },
        ),
        ctx,
    )

    assert _count_chains() == 0


@patch("src.correlation.emit_interface.get_event_publisher")
def test_base_image_idempotent(mock_pub, redis_client):
    mock_pub.return_value.__class__ = type("P", (), {"publish": lambda s, e: None})()

    DIGEST = "sha256:idem0000000004"
    base_id = _insert_finding(
        identity_key="base-idem",
        tool="container_scanning",
        repo=REPO_A,
        detail={"affected_layer": "base", "base_image_digest": DIGEST},
    )
    _insert_finding(
        identity_key="sib-idem",
        tool="container_scanning",
        repo=REPO_B,
        detail={"base_image_digest": DIGEST},
    )

    ctx = _make_ctx(redis_client)
    rule = ContainerBaseImagePropagationRule()
    event = _raw_event(
        "scan.finding",
        event_id="idem-base-evt",
        finding={
            "id": base_id,
            "tool": "container_scanning",
            "org": ORG,
            "repo": REPO_A,
            "detail": {"affected_layer": "base", "base_image_digest": DIGEST},
        },
    )
    rule.evaluate(event, ctx)
    rule.evaluate(event, ctx)

    assert _count_chains() == 1
    assert _count_edges() == 1


# ── Rule 9: CredentialReuseChain ──────────────────────────────────────────────


@patch("src.correlation.emit_interface.get_event_publisher")
def test_credential_reuse_emits_when_hash_appears_twice(mock_pub, redis_client):
    mock_pub.return_value.__class__ = type("P", (), {"publish": lambda s, e: None})()

    HASH = "aabbccddeeff00112233445566778899"
    fid_a = _insert_finding(
        identity_key="cred-a",
        tool="secrets",
        repo=REPO_A,
        detail={"verification_status": "verified", "secret_hash": HASH},
    )
    fid_b = _insert_finding(
        identity_key="cred-b",
        tool="secrets",
        repo=REPO_B,
        detail={"verification_status": "verified", "secret_hash": HASH},
    )

    ctx = _make_ctx(redis_client)
    rule = CredentialReuseChainRule()
    rule.evaluate(
        _raw_event(
            "scan.finding",
            finding={
                "id": fid_b,
                "tool": "secrets",
                "org": ORG,
                "repo": REPO_B,
                "detail": {"verification_status": "verified", "secret_hash": HASH},
            },
        ),
        ctx,
    )

    assert _count_chains() == 1
    edges = _get_edges()
    assert len(edges) == 1
    assert abs(edges[0]["confidence"] - 0.95) < 0.001


@patch("src.correlation.emit_interface.get_event_publisher")
def test_credential_reuse_no_emit_when_unverified(mock_pub, redis_client):
    mock_pub.return_value.__class__ = type("P", (), {"publish": lambda s, e: None})()

    HASH = "unverified112233445566"
    fid_a = _insert_finding(
        identity_key="cred-unver-a",
        tool="secrets",
        repo=REPO_A,
        detail={"verification_status": "unverified", "secret_hash": HASH},
    )
    fid_b = _insert_finding(
        identity_key="cred-unver-b",
        tool="secrets",
        repo=REPO_B,
        detail={"verification_status": "unverified", "secret_hash": HASH},
    )

    ctx = _make_ctx(redis_client)
    rule = CredentialReuseChainRule()
    rule.evaluate(
        _raw_event(
            "scan.finding",
            finding={
                "id": fid_b,
                "tool": "secrets",
                "org": ORG,
                "repo": REPO_B,
                "detail": {"verification_status": "unverified", "secret_hash": HASH},
            },
        ),
        ctx,
    )

    assert _count_chains() == 0


@patch("src.correlation.emit_interface.get_event_publisher")
def test_credential_reuse_no_emit_for_single_occurrence(mock_pub, redis_client):
    mock_pub.return_value.__class__ = type("P", (), {"publish": lambda s, e: None})()

    HASH = "singlehash9900112233"
    fid = _insert_finding(
        identity_key="cred-single",
        tool="secrets",
        detail={"verification_status": "verified", "secret_hash": HASH},
    )

    ctx = _make_ctx(redis_client)
    rule = CredentialReuseChainRule()
    rule.evaluate(
        _raw_event(
            "scan.finding",
            finding={
                "id": fid,
                "tool": "secrets",
                "org": ORG,
                "detail": {"verification_status": "verified", "secret_hash": HASH},
            },
        ),
        ctx,
    )

    assert _count_chains() == 0


@patch("src.correlation.emit_interface.get_event_publisher")
def test_credential_reuse_idempotent(mock_pub, redis_client):
    mock_pub.return_value.__class__ = type("P", (), {"publish": lambda s, e: None})()

    HASH = "idempotent1122334455"
    fid_a = _insert_finding(
        identity_key="cred-idem-a",
        tool="secrets",
        repo=REPO_A,
        detail={"verification_status": "verified", "secret_hash": HASH},
    )
    fid_b = _insert_finding(
        identity_key="cred-idem-b",
        tool="secrets",
        repo=REPO_B,
        detail={"verification_status": "verified", "secret_hash": HASH},
    )

    ctx = _make_ctx(redis_client)
    rule = CredentialReuseChainRule()
    event = _raw_event(
        "scan.finding",
        finding={
            "id": fid_b,
            "tool": "secrets",
            "org": ORG,
            "repo": REPO_B,
            "detail": {"verification_status": "verified", "secret_hash": HASH},
        },
    )
    rule.evaluate(event, ctx)
    rule.evaluate(event, ctx)

    assert _count_chains() == 1
    assert _count_edges() == 1


# ── RulePackLoader ────────────────────────────────────────────────────────────


def test_rule_pack_loader_builtin_has_nine_rules():
    # Phase 11 adds 4 temporal rules; total is now 13.
    loader = RulePackLoader()
    pack = loader.load_builtin()
    assert pack.source == "builtin"
    assert len(pack.rules) == 13
    names = {r.name for r in pack.rules}
    assert "intel_match" in names
    assert "public_exposure_data_handling" in names
    assert "cross_repo_cve_cluster" in names
    assert "container_base_image_propagation" in names
    assert "credential_reuse_chain" in names
    assert "attribution_rollup" in names
    assert "severity_velocity" in names
    assert "mttr_tracking" in names
    assert "anomaly_detection" in names


def test_rule_pack_loader_get_all_rules_dedupes():
    loader = RulePackLoader()
    loader.load_builtin()
    # Load builtin twice — dedup should prevent double-counting
    loader.load_builtin()
    rules = loader.get_all_rules()
    names = [r.name for r in rules]
    assert len(names) == len(set(names))


def test_rule_pack_loader_from_argus_returns_empty_for_null_connector():
    loader = RulePackLoader(argus_connector=NullArgusConnector())
    packs = loader.load_from_argus()
    assert packs == []


def test_rule_pack_loader_from_path(tmp_path: Path):
    pack_file = tmp_path / "custom_pack.py"
    pack_file.write_text(
        "from src.correlation.rule_pack_loader import RulePack\n"
        "from src.correlation.rules.lifecycle import LifecycleRule\n"
        "RULE_PACK = RulePack(pack_id='custom', version='1.0', rules=[LifecycleRule()], source='local-file')\n"
    )
    loader = RulePackLoader()
    pack = loader.load_from_path(pack_file)
    assert pack.pack_id == "custom"
    assert pack.source == "local-file"
    assert len(pack.rules) == 1
    assert loader.pack_count == 1


def test_rule_pack_loader_from_path_missing_file(tmp_path: Path):
    loader = RulePackLoader()
    with pytest.raises(FileNotFoundError):
        loader.load_from_path(tmp_path / "nonexistent.py")


# ── Engine hot-reload ─────────────────────────────────────────────────────────


def test_engine_reload_rules_swaps_to_nine_builtins(redis_container):
    # Phase 11 adds 4 temporal rules; total is now 13.
    engine = CorrelationEngine(
        stream_config=_stream_cfg(redis_container),
        redis_config=_redis_cfg(redis_container),
    )
    register_builtin_rules(engine)
    assert len(engine._rules) == 13

    loader = RulePackLoader()
    loader.load_builtin()
    pack_count = engine.reload_rules(loader=loader)

    assert pack_count == 1
    assert len(engine._rules) == 13


def test_engine_reload_adds_rules_from_extra_pack(redis_container):
    engine = CorrelationEngine(
        stream_config=_stream_cfg(redis_container),
        redis_config=_redis_cfg(redis_container),
    )
    register_builtin_rules(engine)

    # Simulate an Argus pack contributing one extra rule
    from src.correlation.rules.lifecycle import LifecycleRule as _LC

    class ExtraRule(_LC):
        name = "extra_rule_from_argus"

    loader = RulePackLoader()
    loader.load_builtin()
    loader._packs["argus-extra"] = RulePack(
        pack_id="argus-extra",
        version="1.0",
        rules=[ExtraRule()],
        source="argus",
    )
    engine.reload_rules(loader=loader)

    # 9 builtin + 1 argus = 10 (lifecycle name differs due to subclass override)
    assert "extra_rule_from_argus" in engine._rules


def test_engine_reload_does_not_restart_running_engine(redis_container):
    engine = CorrelationEngine(
        stream_config=_stream_cfg(redis_container),
        redis_config=_redis_cfg(redis_container),
    )
    register_builtin_rules(engine)
    engine.start()

    try:
        loader = RulePackLoader()
        loader.load_builtin()
        engine.reload_rules(loader=loader)
        assert engine.is_running
    finally:
        engine.stop(timeout=3.0)


# ── register_builtin_rules count updated to 13 (Phase 11 adds 4 temporal) ────


def test_register_builtin_rules_now_has_nine(redis_container):
    engine = CorrelationEngine(
        stream_config=_stream_cfg(redis_container),
        redis_config=_redis_cfg(redis_container),
    )
    register_builtin_rules(engine)
    assert len(engine._rules) == 13
    expected = {
        "intel_match", "reachable_cve", "secret_to_resource", "lifecycle",
        "epss_escalation", "public_exposure_data_handling", "cross_repo_cve_cluster",
        "container_base_image_propagation", "credential_reuse_chain",
        "attribution_rollup", "severity_velocity", "mttr_tracking", "anomaly_detection",
    }
    assert set(engine._rules.keys()) == expected
