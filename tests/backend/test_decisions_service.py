"""Tests for the decisions service layer — policy parsing, blocker projection,
and the Go/No-Go evaluation predicate.

The DB-touching paths use a real db_session from conftest so we exercise the
SQL query against Postgres rather than mocking SQLAlchemy.

Block-path coverage in decisions/service.py is deferred pending the
`fix/decisions-finding-repo` hotfix branch (PR #578). The `_fetch_blockers`
tests in this file assert empty result sets only — driving a real Finding row
through the projector currently crashes with `AttributeError` because
`_finding_to_blocker` reads `finding.repo`, which was removed from the Finding
model during the asset-identity refactor. The hotfix rewires the projector to
read `Asset.display_name` via JOIN. Once that lands on `main-v2`, append the
"blocker projector returns expected shape" coverage here (see the NOTE at the
bottom of this file).
"""
from __future__ import annotations

from types import SimpleNamespace
from uuid import uuid4

import pytest
import pytest_asyncio
from sqlalchemy import delete

from src.db.models import Asset, Finding
from src.decisions.service import (
    DEFAULT_BLOCK_ON,
    DecisionPolicy,
    DecisionService,
    VALID_SEVERITIES,
    _finding_to_blocker,
    parse_policy,
)




def test_parse_policy_none_returns_defaults():
    out = parse_policy(None)
    assert out.block_on == DEFAULT_BLOCK_ON


def test_parse_policy_empty_dict_returns_defaults():
    out = parse_policy({})
    assert out.block_on == DEFAULT_BLOCK_ON


def test_parse_policy_string_block_on_coerced_to_single_entry_list():
    out = parse_policy({"block_on": "high"})
    assert out.block_on == ("high",)


def test_parse_policy_lowercases_severity_entries():
    out = parse_policy({"block_on": ["HIGH", "Critical"]})
    assert out.block_on == ("high", "critical")


def test_parse_policy_rejects_non_dict_payload():
    with pytest.raises(ValueError, match="policy must be an object"):
        parse_policy("critical")  # type: ignore[arg-type]


def test_parse_policy_rejects_non_list_block_on():
    with pytest.raises(ValueError, match="must be a list"):
        parse_policy({"block_on": 42})


def test_parse_policy_rejects_non_string_entries():
    with pytest.raises(ValueError, match="must be strings"):
        parse_policy({"block_on": [1, 2]})


def test_parse_policy_rejects_unknown_severity():
    with pytest.raises(ValueError, match="invalid severity"):
        parse_policy({"block_on": ["catastrophic"]})


def test_parse_policy_drops_blank_entries_and_falls_back_to_default():
    # An all-whitespace list collapses to empty, which the helper must rescue
    # with the documented default rather than producing an open policy.
    out = parse_policy({"block_on": ["   ", ""]})
    assert out.block_on == DEFAULT_BLOCK_ON


def test_parse_policy_preserves_order_and_strips_whitespace():
    out = parse_policy({"block_on": [" high ", "low"]})
    assert out.block_on == ("high", "low")


def test_valid_severities_is_locked_set():
    assert VALID_SEVERITIES == frozenset({"critical", "high", "medium", "low"})




def test_finding_to_blocker_lowercases_severity_and_falls_back_title():
    finding = SimpleNamespace(
        id=1,
        tool="dependencies_scanning",
        severity="HIGH",
        state="open",
        identity_key="key-1",
        title=None,
        cve_id="CVE-2024-1234",
    )
    out = _finding_to_blocker(finding, repo="acme/api")
    assert out["severity"] == "high"
    assert out["title"] == "key-1"  # falls back to identity_key
    assert out["cve"] == "CVE-2024-1234"
    assert out["repo"] == "acme/api"


def test_finding_to_blocker_severity_blank_becomes_none():
    finding = SimpleNamespace(
        id=2, tool="t", severity="", state="open",
        identity_key="k", title="t", cve_id=None,
    )
    out = _finding_to_blocker(finding, repo=None)
    assert out["severity"] is None
    assert out["repo"] is None


def test_finding_to_blocker_does_not_read_repo_off_finding():
    """Regression: Finding model has no `repo` column; reading one would
    AttributeError at runtime. The caller passes Asset.display_name via JOIN."""
    # A real-ish Finding stand-in: no `repo` attribute defined at all.
    class FakeFinding:
        id = 3
        tool = "secrets"
        severity = "critical"
        state = "open"
        identity_key = "secret-1"
        title = "leaked key"
        cve_id = None

    out = _finding_to_blocker(FakeFinding(), repo="acme/api")
    assert out["repo"] == "acme/api"




@pytest_asyncio.fixture
async def decisions_fixture(db_session):
    """Seed one asset and one open low-severity finding scoped to it.

    The service's repo-resolver matches on the trailing segment of
    external_ref, so the asset uses external_ref `<source>:<org>/api`. The
    Finding model has no `org`/`repo` columns; scoping flows through asset_id.
    """
    org = f"acme-{uuid4().hex[:6]}"
    asset = Asset(
        type="repo",
        source="source_connection",
        external_ref=f"github:{org}/api",
        display_name=f"{org}/api",
    )
    db_session.add(asset)
    await db_session.flush()
    low = Finding(
        tool="dependencies_scanning",
        identity_key=f"d-{uuid4()}",
        state="open",
        severity="low",
        title="cosmetic",
        detail={},
        asset_id=str(asset.id),
    )
    db_session.add(low)
    await db_session.commit()
    yield SimpleNamespace(org=org, asset_id=str(asset.id), low=low)
    await db_session.execute(delete(Finding).where(Finding.id == low.id))
    await db_session.execute(delete(Asset).where(Asset.id == asset.id))
    await db_session.commit()


@pytest.mark.asyncio
async def test_evaluate_requires_org_id_or_asset_ids(db_session):
    svc = DecisionService()
    with pytest.raises(ValueError, match="org_id is required"):
        await svc.evaluate(
            org_id=None, repo=None, policy=DecisionPolicy(), session=db_session,
        )


@pytest.mark.asyncio
async def test_evaluate_empty_asset_ids_returns_allow(db_session):
    svc = DecisionService()
    out = await svc.evaluate(
        org_id=None, repo=None, policy=DecisionPolicy(),
        session=db_session, asset_ids=[],
    )
    assert out["decision"] == "allow"
    assert out["blockers"] == []
    assert out["source"] == "backend"


@pytest.mark.asyncio
async def test_evaluate_allows_when_no_findings_match_block_severity(
    db_session, decisions_fixture,
):
    # Seeded finding is low; policy blocks only critical, so verdict is allow.
    svc = DecisionService()
    out = await svc.evaluate(
        org_id=decisions_fixture.org, repo="api",
        policy=DecisionPolicy(block_on=("critical",)),
        session=db_session,
    )
    assert out["decision"] == "allow"
    assert out["blockers"] == []
    assert "No open findings" in out["rationale"]


@pytest.mark.asyncio
async def test_evaluate_allows_when_org_has_no_matching_repo(db_session):
    svc = DecisionService()
    out = await svc.evaluate(
        org_id=f"unknown-{uuid4().hex[:6]}", repo="api",
        policy=DecisionPolicy(block_on=("critical",)),
        session=db_session,
    )
    # No assets resolve → no findings → allow
    assert out["decision"] == "allow"
    assert out["blockers"] == []


@pytest.mark.asyncio
async def test_evaluate_resolves_asset_ids_from_org_when_no_repo_specified(
    db_session, decisions_fixture,
):
    # Without `repo`, the resolver should match all `<org>/<anything>` repo
    # assets. The seeded asset matches; no critical findings → allow.
    svc = DecisionService()
    out = await svc.evaluate(
        org_id=decisions_fixture.org, repo=None,
        policy=DecisionPolicy(block_on=("critical",)),
        session=db_session,
    )
    assert out["decision"] == "allow"


@pytest.mark.asyncio
async def test_evaluate_allow_rationale_lists_block_severities_sorted(
    db_session, decisions_fixture,
):
    # Allow rationale must surface the deduped + sorted block_on severities so
    # CI logs make the policy that produced the verdict visible to the human.
    svc = DecisionService()
    out = await svc.evaluate(
        org_id=decisions_fixture.org, repo="api",
        policy=DecisionPolicy(block_on=("high", "critical", "high")),
        session=db_session,
    )
    assert out["decision"] == "allow"
    # sorted(set(("high","critical","high"))) → ["critical", "high"]
    assert "critical, high" in out["rationale"]


@pytest.mark.asyncio
async def test_evaluate_response_shape_locked(db_session):
    # Lock the four-key contract so downstream CLI/UI parsers don't drift.
    svc = DecisionService()
    out = await svc.evaluate(
        org_id=None, repo=None, policy=DecisionPolicy(),
        session=db_session, asset_ids=[],
    )
    assert set(out.keys()) == {"decision", "blockers", "rationale", "source"}
    assert out["source"] == "backend"


@pytest.mark.asyncio
async def test_resolve_asset_ids_from_org_repo_returns_empty_when_org_id_blank(
    db_session,
):
    # Direct call to the private helper exercises the empty-org_id early return
    # — the public evaluate() guards against it, so this branch can only be
    # hit by internal callers and the regression risk would otherwise be hidden.
    svc = DecisionService()
    rows = await svc._resolve_asset_ids_from_org_repo(
        org_id="", repo="api", session=db_session,
    )
    assert rows == []
    rows_none = await svc._resolve_asset_ids_from_org_repo(
        org_id=None, repo="api", session=db_session,
    )
    assert rows_none == []


@pytest.mark.asyncio
async def test_resolve_asset_ids_from_org_repo_returns_all_org_repos_when_repo_none(
    db_session,
):
    # The "no repo" branch must use the org-wide pattern and only match
    # type='repo' assets (skipping image assets).
    org = f"acme-{uuid4().hex[:6]}"
    repo_asset = Asset(
        type="repo",
        source="source_connection",
        external_ref=f"github:{org}/api",
        display_name=f"{org}/api",
    )
    image_asset = Asset(
        type="image",
        source="source_connection",
        external_ref=f"ecr:{org}/svc",
        display_name=f"{org}/svc",
    )
    db_session.add_all([repo_asset, image_asset])
    await db_session.commit()
    try:
        svc = DecisionService()
        rows = await svc._resolve_asset_ids_from_org_repo(
            org_id=org, repo=None, session=db_session,
        )
        # The repo asset matches; the image asset is filtered out by type='repo'.
        assert str(repo_asset.id) in rows
        assert str(image_asset.id) not in rows
    finally:
        await db_session.execute(delete(Asset).where(Asset.id.in_([repo_asset.id, image_asset.id])))
        await db_session.commit()


@pytest.mark.asyncio
async def test_evaluate_block_path_emits_blocker_with_repo_display_name(
    db_session, decisions_fixture,
):
    """Regression for the production AttributeError on Finding.repo.

    Previously _finding_to_blocker did ``finding.repo`` — but Finding has no
    such column post asset-identity refactor. The block path crashed with
    AttributeError as soon as any open critical finding existed. This test
    seeds a critical finding and asserts a clean blocker dict comes back
    with the repo display_name pulled via JOIN.
    """
    critical = Finding(
        tool="dependencies",
        identity_key=f"c-{uuid4()}",
        state="open",
        severity="critical",
        title="rce in left-pad",
        cve_id="CVE-2024-9999",
        detail={},
        asset_id=decisions_fixture.asset_id,
    )
    db_session.add(critical)
    await db_session.commit()
    try:
        svc = DecisionService()
        out = await svc.evaluate(
            org_id=decisions_fixture.org, repo="api",
            policy=DecisionPolicy(block_on=("critical",)),
            session=db_session,
        )
        assert out["decision"] == "block"
        assert len(out["blockers"]) == 1
        blocker = out["blockers"][0]
        assert blocker["severity"] == "critical"
        assert blocker["cve"] == "CVE-2024-9999"
        # The crash that this test guards against: blocker["repo"] used to be
        # produced by reading the non-existent Finding.repo. It now reads
        # Asset.display_name via JOIN, which is "<org>/api" per the fixture.
        assert blocker["repo"] == f"{decisions_fixture.org}/api"
    finally:
        await db_session.execute(delete(Finding).where(Finding.id == critical.id))
        await db_session.commit()


@pytest.mark.asyncio
async def test_resolve_asset_ids_from_org_repo_matches_across_source_types(
    db_session,
):
    # external_ref uses `<source_type>:<owner>/<name>` — the resolver must
    # match the trailing segment regardless of source so the same org+repo
    # works for github / gitlab / bitbucket without the CI caller knowing.
    org = f"acme-{uuid4().hex[:6]}"
    repo = "platform"
    gh = Asset(
        type="repo", source="source_connection",
        external_ref=f"github:{org}/{repo}", display_name=f"{org}/{repo}",
    )
    gl = Asset(
        type="repo", source="source_connection",
        external_ref=f"gitlab:{org}/{repo}", display_name=f"gl-{org}/{repo}",
    )
    db_session.add_all([gh, gl])
    await db_session.commit()
    try:
        svc = DecisionService()
        rows = await svc._resolve_asset_ids_from_org_repo(
            org_id=org, repo=repo, session=db_session,
        )
        assert str(gh.id) in rows
        assert str(gl.id) in rows
    finally:
        await db_session.execute(delete(Asset).where(Asset.id.in_([gh.id, gl.id])))
        await db_session.commit()


@pytest.mark.asyncio
async def test_fetch_blockers_excludes_non_open_findings(db_session):
    # Closed/fixed/dismissed findings must never block — lock that filter
    # so a future regression that fans out by state can't silently re-include
    # historical noise.
    asset = Asset(
        type="repo", source="source_connection",
        external_ref=f"github:acme-{uuid4().hex[:6]}/api",
        display_name="acme/api",
    )
    db_session.add(asset)
    await db_session.flush()
    fixed = Finding(
        tool="dependencies_scanning",
        identity_key=f"k-{uuid4()}",
        state="fixed", severity="critical",
        title="old", detail={}, asset_id=str(asset.id),
    )
    dismissed = Finding(
        tool="dependencies_scanning",
        identity_key=f"k-{uuid4()}",
        state="dismissed", severity="critical",
        title="ignored", detail={}, asset_id=str(asset.id),
    )
    db_session.add_all([fixed, dismissed])
    await db_session.commit()
    try:
        svc = DecisionService()
        rows = await svc._fetch_blockers(
            org_id=None, repo=None, block_on=("critical",),
            session=db_session, asset_ids=[str(asset.id)],
        )
        assert rows == []
    finally:
        await db_session.execute(delete(Finding).where(Finding.id.in_([fixed.id, dismissed.id])))
        await db_session.execute(delete(Asset).where(Asset.id == asset.id))
        await db_session.commit()


@pytest.mark.asyncio
async def test_fetch_blockers_severity_below_block_on_set_not_returned(
    db_session, decisions_fixture,
):
    # Seeded fixture has only a low-severity finding; ("critical", "high")
    # policy must not pick it up. Pins the lower-severity branch of the IN
    # filter (no rows returned → blocker projector never invoked).
    svc = DecisionService()
    rows = await svc._fetch_blockers(
        org_id=None, repo=None, block_on=("critical", "high"),
        session=db_session, asset_ids=[decisions_fixture.asset_id],
    )
    assert rows == []


@pytest.mark.asyncio
async def test_fetch_blockers_asset_scope_filter_excludes_unrelated_assets_no_blockers(
    db_session, decisions_fixture,
):
    # Cross-asset isolation: scoping to a fresh UUID must yield no blockers
    # even though the seeded asset has an open finding. Confirms the
    # asset_id IN filter is applied (no rows returned).
    svc = DecisionService()
    rows = await svc._fetch_blockers(
        org_id=None, repo=None, block_on=("low",),
        session=db_session, asset_ids=[str(uuid4())],
    )
    assert rows == []


@pytest.mark.asyncio
async def test_fetch_blockers_empty_asset_ids_short_circuits_to_empty(
    db_session,
):
    # Belt-and-suspenders next to test_evaluate_empty_asset_ids_returns_allow:
    # the same short-circuit must also work when _fetch_blockers is called
    # directly, so any future caller that bypasses evaluate() still benefits.
    svc = DecisionService()
    rows = await svc._fetch_blockers(
        org_id=None, repo=None, block_on=("critical",),
        session=db_session, asset_ids=[],
    )
    assert rows == []


@pytest.mark.asyncio
async def test_evaluate_block_path_emits_blocker_with_null_repo_when_asset_missing(
    db_session,
):
    """Secrets findings carry asset_id=NULL by design — the LEFT JOIN must
    still emit the blocker, just with repo=None."""
    secret = Finding(
        tool="secrets",
        identity_key=f"s-{uuid4()}",
        state="open",
        severity="critical",
        title="leaked AWS key",
        detail={},
        asset_id=None,
    )
    db_session.add(secret)
    await db_session.commit()
    try:
        svc = DecisionService()
        # asset_ids=None+repo=None resolves to no asset filter when org has none;
        # bypass that by passing an empty asset_ids list… no, we WANT the secret
        # in scope, so call without asset filter via an admin-style path that
        # doesn't constrain by asset_id. Easiest: call _fetch_blockers directly.
        out = await svc._fetch_blockers(
            org_id=None, repo=None, block_on=("critical",),
            session=db_session, asset_ids=None,
        )
        # The secrets finding is in scope when no asset filter is applied.
        secret_blockers = [b for b in out if b["identity_key"] == secret.identity_key]
        assert len(secret_blockers) == 1
        assert secret_blockers[0]["repo"] is None
    finally:
        await db_session.execute(delete(Finding).where(Finding.id == secret.id))
        await db_session.commit()
