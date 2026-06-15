"""Tests for cross-scanner findings serialization with KEV/CWE enrichment."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
import pytest_asyncio
from sqlalchemy import delete

from src.findings.service import (
    _finding_to_dict,
    _normalize_filters,
    FindingsListFilters,
    MAX_ASSIGNABLE_USERS_LIMIT,
    VALID_SORTS,
    assign_finding,
    list_assignable_users,
)
from src.db.models import Asset, Finding, User


class FakeKevLookup:
    def __init__(self, kev_set: set[str], cwes: dict[str, list[str]]):
        self._kev = kev_set
        self._cwes = cwes

    def is_kev(self, cve: str | None) -> bool:
        return cve in self._kev if cve else False

    def first_cwe(self, cve: str | None) -> str | None:
        if not cve:
            return None
        cwes = self._cwes.get(cve)
        return cwes[0] if cwes else None


def make_finding(**overrides) -> Finding:
    f = Finding()
    f.id = overrides.get("id", 1)
    f.tool = overrides.get("tool", "dependencies")
    f.severity = overrides.get("severity", "critical")
    f.state = overrides.get("state", "open")
    f.title = overrides.get("title", "log4j-core 2.14.0")
    f.cve_id = overrides.get("cve_id", "CVE-2021-44228")
    f.identity_key = overrides.get("identity_key", "key-1")
    f.repo = overrides.get("repo", "acme/api")
    f.package_name = overrides.get("package_name", "log4j-core")
    f.file_path = overrides.get("file_path", "pom.xml")
    f.org = overrides.get("org", "org-1")
    f.detail = overrides.get("detail", {})
    f.created_at = overrides.get("created_at", None)
    f.updated_at = overrides.get("updated_at", None)
    f.risk_score = overrides.get("risk_score", None)
    f.assignee_user_id = overrides.get("assignee_user_id", None)
    return f


def test_finding_dict_includes_kev_true_when_cve_in_kev_set():
    lookup = FakeKevLookup({"CVE-2021-44228"}, {"CVE-2021-44228": ["CWE-502"]})
    out = _finding_to_dict(make_finding(), kev_lookup=lookup)
    assert out["kev"] is True
    assert out["cwe"] == "CWE-502"


def test_finding_dict_kev_false_when_cve_absent_from_kev_set():
    lookup = FakeKevLookup(set(), {})
    out = _finding_to_dict(make_finding(cve_id="CVE-9999-9999"), kev_lookup=lookup)
    assert out["kev"] is False
    assert out["cwe"] is None


def test_finding_dict_kev_false_when_finding_has_no_cve():
    lookup = FakeKevLookup({"CVE-X"}, {"CVE-X": ["CWE-1"]})
    out = _finding_to_dict(make_finding(cve_id=None), kev_lookup=lookup)
    assert out["kev"] is False
    assert out["cwe"] is None


def test_finding_dict_without_lookup_returns_kev_false_and_cwe_none():
    """Default no-op lookup: callers that don't supply one shouldn't crash."""
    out = _finding_to_dict(make_finding(cve_id="CVE-2021-44228"))
    assert out["kev"] is False
    assert out["cwe"] is None


def test_valid_sorts_includes_new_options():
    assert "severity_age" in VALID_SORTS
    assert "epss" in VALID_SORTS
    assert "risk_score" in VALID_SORTS
    assert "newest" in VALID_SORTS
    assert "oldest" in VALID_SORTS


def test_normalize_filters_accepts_first_seen_after():
    cutoff = datetime.now(timezone.utc) - timedelta(days=7)
    f = _normalize_filters(FindingsListFilters(org_id="org-1", first_seen_after=cutoff))
    assert f.first_seen_after == cutoff


def test_normalize_filters_rejects_invalid_sort():
    with pytest.raises(ValueError):
        _normalize_filters(FindingsListFilters(org_id="org-1", sort="invalid"))


def test_normalize_filters_accepts_risk_score_sort():
    f = _normalize_filters(FindingsListFilters(org_id="org-1", sort="risk_score"))
    assert f.sort == "risk_score"


def test_normalize_filters_accepts_risk_score_min():
    f = _normalize_filters(FindingsListFilters(org_id="org-1", risk_score_min=70))
    assert f.risk_score_min == 70


def test_normalize_filters_clamps_risk_score_min_above_100():
    f = _normalize_filters(FindingsListFilters(org_id="org-1", risk_score_min=150))
    assert f.risk_score_min == 100


def test_normalize_filters_clamps_negative_risk_score_min_to_0():
    f = _normalize_filters(FindingsListFilters(org_id="org-1", risk_score_min=-10))
    assert f.risk_score_min == 0


def test_finding_dict_includes_risk_score_when_set():
    out = _finding_to_dict(make_finding())
    assert out["risk_score"] is None
    finding = make_finding()
    finding.risk_score = 82
    out = _finding_to_dict(finding)
    assert out["risk_score"] == 82


def test_normalize_filters_accepts_assignee_user_id():
    f = _normalize_filters(FindingsListFilters(org_id="org-1", assignee_user_id="user-42"))
    assert f.assignee_user_id == "user-42"


def test_normalize_filters_strips_whitespace_on_assignee():
    f = _normalize_filters(FindingsListFilters(org_id="org-1", assignee_user_id="  user-42  "))
    assert f.assignee_user_id == "user-42"


def test_normalize_filters_empty_assignee_becomes_none():
    f = _normalize_filters(FindingsListFilters(org_id="org-1", assignee_user_id=""))
    assert f.assignee_user_id is None


def test_normalize_filters_caps_assignee_at_255_chars():
    long_id = "u" * 400
    f = _normalize_filters(FindingsListFilters(org_id="org-1", assignee_user_id=long_id))
    assert f.assignee_user_id is not None
    assert len(f.assignee_user_id) == 255


def test_finding_dict_includes_assignee_user_id_when_set():
    out = _finding_to_dict(make_finding())
    assert out["assignee_user_id"] is None
    finding = make_finding(assignee_user_id="user-42")
    out = _finding_to_dict(finding)
    assert out["assignee_user_id"] == "user-42"


def test_normalize_filters_accepts_more_filters_fields():
    f = _normalize_filters(FindingsListFilters(
        org_id="org-1",
        cwe="CWE-502",
        kev=True,
        epss_min=0.5,
    ))
    assert f.cwe == "CWE-502"
    assert f.kev is True
    assert f.epss_min == 0.5


def test_normalize_filters_clamps_epss_range():
    f = _normalize_filters(FindingsListFilters(org_id="org-1", epss_min=2.0))
    assert f.epss_min == 1.0
    f = _normalize_filters(FindingsListFilters(org_id="org-1", epss_min=-0.5))
    assert f.epss_min == 0.0


def test_normalize_filters_uppercases_cwe():
    f = _normalize_filters(FindingsListFilters(org_id="org-1", cwe="cwe-502"))
    assert f.cwe == "CWE-502"


def test_normalize_filters_clamps_negative_page_to_1():
    f = _normalize_filters(FindingsListFilters(org_id="org-1", page=-5))
    assert f.page == 1


def test_normalize_filters_clamps_zero_page_to_1():
    f = _normalize_filters(FindingsListFilters(org_id="org-1", page=0))
    assert f.page == 1


def test_normalize_filters_preserves_valid_page():
    f = _normalize_filters(FindingsListFilters(org_id="org-1", page=3))
    assert f.page == 3


# ─── assign_finding (DB-backed) ─────────────────────────────────────────────


@pytest_asyncio.fixture
async def assign_finding_fixture(db_session):
    """Seed one Asset, one Finding bound to it, and two Users; clean up at teardown.

    The conftest db_session commits across tests, so leaked rows would
    otherwise collide with the per-tool unique constraint on identity_key.
    """
    asset = Asset(
        type="repo",
        source="source_connection",
        external_ref=f"github:acme/{uuid4().hex[:8]}",
        display_name=f"acme/{uuid4().hex[:8]}",
    )
    db_session.add(asset)
    await db_session.flush()
    user_a = User(id=f"user-{uuid4()}", username=f"a-{uuid4()}", email="a@example.com")
    user_b = User(id=f"user-{uuid4()}", username=f"b-{uuid4()}", email="b@example.com")
    finding = Finding(
        tool="dependencies",
        identity_key=f"key-{uuid4()}",
        state="open",
        severity="critical",
        title="log4j-core",
        detail={},
        asset_id=str(asset.id),
    )
    db_session.add_all([user_a, user_b, finding])
    await db_session.commit()
    asset_ids = [str(asset.id)]
    yield finding, user_a, user_b, asset_ids
    await db_session.execute(delete(Finding).where(Finding.id == finding.id))
    await db_session.execute(delete(User).where(User.id.in_((user_a.id, user_b.id))))
    await db_session.execute(delete(Asset).where(Asset.id == asset.id))
    await db_session.commit()


@pytest.mark.asyncio
async def test_assign_finding_sets_assignee_for_known_user(db_session, assign_finding_fixture):
    finding, user_a, _, asset_ids = assign_finding_fixture
    updated, previous = await assign_finding(finding.id, user_a.id, db_session, asset_ids)
    assert previous is None
    assert updated.assignee_user_id == user_a.id


@pytest.mark.asyncio
async def test_assign_finding_clears_assignee_when_null(db_session, assign_finding_fixture):
    finding, user_a, _, asset_ids = assign_finding_fixture
    await assign_finding(finding.id, user_a.id, db_session, asset_ids)
    updated, previous = await assign_finding(finding.id, None, db_session, asset_ids)
    assert previous == user_a.id
    assert updated.assignee_user_id is None


@pytest.mark.asyncio
async def test_assign_finding_rejects_unknown_user(db_session, assign_finding_fixture):
    finding, _, _, asset_ids = assign_finding_fixture
    with pytest.raises(ValueError, match="unknown user"):
        await assign_finding(finding.id, "user-does-not-exist", db_session, asset_ids)


@pytest.mark.asyncio
async def test_assign_finding_raises_lookup_error_for_missing_finding(db_session):
    with pytest.raises(LookupError):
        await assign_finding(99_999_999, None, db_session, ["any-asset-id"])


@pytest.mark.asyncio
async def test_assign_finding_empty_string_clears_like_null(db_session, assign_finding_fixture):
    finding, user_a, _, asset_ids = assign_finding_fixture
    await assign_finding(finding.id, user_a.id, db_session, asset_ids)
    updated, previous = await assign_finding(finding.id, "   ", db_session, asset_ids)
    assert previous == user_a.id
    assert updated.assignee_user_id is None


@pytest.mark.asyncio
async def test_assign_finding_404s_when_asset_out_of_scope(db_session, assign_finding_fixture):
    finding, user_a, _, _ = assign_finding_fixture
    with pytest.raises(LookupError):
        await assign_finding(finding.id, user_a.id, db_session, ["unrelated-asset-id"])


@pytest.mark.asyncio
async def test_assign_finding_404s_when_scope_is_empty(db_session, assign_finding_fixture):
    finding, user_a, _, _ = assign_finding_fixture
    with pytest.raises(LookupError):
        await assign_finding(finding.id, user_a.id, db_session, [])


# ─── list_assignable_users (DB-backed) ──────────────────────────────────────


@pytest_asyncio.fixture
async def assignable_users_fixture(db_session):
    """Seed three users — two active, one disabled — and clean up at teardown."""
    suffix = uuid4().hex[:8]
    alice = User(id=f"u-alice-{suffix}", username=f"alice-{suffix}", email=f"alice-{suffix}@example.com", status="active")
    bob = User(id=f"u-bob-{suffix}", username=f"bob-{suffix}", email=f"bob-{suffix}@example.com", status="active")
    inactive = User(id=f"u-inactive-{suffix}", username=f"zzz-inactive-{suffix}", email=f"zzz-{suffix}@example.com", status="disabled")
    db_session.add_all([alice, bob, inactive])
    await db_session.commit()
    yield alice, bob, inactive, suffix
    await db_session.execute(delete(User).where(User.id.in_((alice.id, bob.id, inactive.id))))
    await db_session.commit()


@pytest.mark.asyncio
async def test_list_assignable_users_excludes_disabled(db_session, assignable_users_fixture):
    _, _, inactive, suffix = assignable_users_fixture
    rows = await list_assignable_users(db_session, q=suffix, limit=10)
    assert all(r["id"] != inactive.id for r in rows)


@pytest.mark.asyncio
async def test_list_assignable_users_matches_username_substring(db_session, assignable_users_fixture):
    alice, _, _, _ = assignable_users_fixture
    rows = await list_assignable_users(db_session, q=alice.username[:5])
    assert any(r["id"] == alice.id for r in rows)


@pytest.mark.asyncio
async def test_list_assignable_users_matches_email_substring(db_session, assignable_users_fixture):
    alice, _, _, _ = assignable_users_fixture
    rows = await list_assignable_users(db_session, q=alice.email.split("@")[0])
    assert any(r["id"] == alice.id for r in rows)


@pytest.mark.asyncio
async def test_list_assignable_users_caps_limit_at_max(db_session, assignable_users_fixture):
    rows = await list_assignable_users(db_session, limit=999)
    assert len(rows) <= MAX_ASSIGNABLE_USERS_LIMIT


@pytest.mark.asyncio
async def test_list_assignable_users_empty_q_returns_recent(db_session, assignable_users_fixture):
    rows = await list_assignable_users(db_session, q="", limit=50)
    assert isinstance(rows, list)


@pytest.mark.asyncio
async def test_list_assignable_users_returns_id_username_email_only(db_session, assignable_users_fixture):
    alice, _, _, suffix = assignable_users_fixture
    rows = await list_assignable_users(db_session, q=suffix, limit=5)
    assert all(set(r.keys()) == {"id", "username", "email"} for r in rows)


@pytest_asyncio.fixture
async def _isolated_upsert_finding(db_session):
    """Patch upsert_finding side effects (blob upload, compliance mapper) so
    the new asset_id tests can write rows without depending on MinIO or the
    compliance_control_mappings table (not present in the test DB)."""
    from unittest.mock import AsyncMock, patch
    with (
        patch("src.shared.finding_queries.put_detail_blob", return_value=None),
        patch("src.shared.finding_queries.delete_detail_blob", return_value=None),
        patch("src.compliance.auto_mapper.apply_finding_mappings", new=AsyncMock(return_value=None)),
    ):
        yield
    from src.db.models import Asset
    await db_session.execute(delete(Finding).where(Finding.identity_key.like("ut-upsert-%")))
    await db_session.execute(delete(Asset).where(Asset.external_ref == "github:acme/upsert-test"))
    await db_session.commit()


@pytest.mark.asyncio
async def test_upsert_finding_writes_asset_id(db_session, _isolated_upsert_finding):
    from src.assets.service import upsert_asset
    from src.shared.finding_queries import upsert_finding

    asset_id = await upsert_asset(
        db_session, type="repo", source="source_connection",
        external_ref="github:acme/upsert-test", display_name="acme/upsert-test",
    )
    f = await upsert_finding(
        db_session, tool="dependencies", asset_id=asset_id,
        org="acme", repo="upsert-test",
        identity_key=f"ut-upsert-{uuid4()}", state="open", severity="high",
        detail={"title": "test"},
    )
    assert f.asset_id == asset_id


@pytest.mark.asyncio
async def test_upsert_finding_accepts_null_asset_id_for_secrets(db_session, _isolated_upsert_finding):
    from src.shared.finding_queries import upsert_finding

    f = await upsert_finding(
        db_session, tool="secrets", asset_id=None,
        org="acme", repo=None,
        identity_key=f"ut-upsert-{uuid4()}", state="open", severity=None,
        detail={},
    )
    assert f.asset_id is None


# ---------------------------------------------------------------------------
# Verdict filter normalization
# ---------------------------------------------------------------------------

def test_normalize_filters_accepts_known_verdict():
    f = _normalize_filters(FindingsListFilters(org_id="org-1", verdict="confirmed"))
    assert f.verdict == "confirmed"


def test_normalize_filters_accepts_legacy_verdict_filter():
    f = _normalize_filters(FindingsListFilters(org_id="org-1", verdict="legacy"))
    assert f.verdict == "legacy"


def test_normalize_filters_accepts_all_verdict_filter():
    f = _normalize_filters(FindingsListFilters(org_id="org-1", verdict="all"))
    assert f.verdict == "all"


def test_normalize_filters_rejects_unknown_verdict():
    with pytest.raises(ValueError, match="invalid verdict"):
        _normalize_filters(FindingsListFilters(org_id="org-1", verdict="bogus"))


def test_normalize_filters_defaults_verdict_to_none():
    f = _normalize_filters(FindingsListFilters(org_id="org-1"))
    assert f.verdict is None
