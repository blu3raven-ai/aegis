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
    _secret_verified,
    advisory_intel,
    count_related_repos,
    finding_advisory,
    list_related_findings,
    FindingsListFilters,
    MAX_ASSIGNABLE_USERS_LIMIT,
    VALID_SORTS,
    assign_finding,
    list_assignable_users,
)
from src.db.models import Asset, Finding, Grant, User


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
    f.recommended_fix = overrides.get("recommended_fix", None)
    f.evidence = overrides.get("evidence", None)
    f.exploit_chain = overrides.get("exploit_chain", None)
    f.verification_metadata = overrides.get("verification_metadata", None)
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
    assert out["epss_percentile"] is None


def test_finding_dict_exposes_asset_id_and_rule_id_for_accept_risk():
    """The drawer's accept-as-intended-risk action needs the finding's asset id
    and the raw rule id to scope a carve-out to exactly this asset + rule."""
    f = make_finding(detail={"ruleId": "python.lang.eval"})
    f.asset_id = "11111111-1111-1111-1111-111111111111"
    out = _finding_to_dict(f)
    assert out["asset_id"] == "11111111-1111-1111-1111-111111111111"
    assert out["rule_id"] == "python.lang.eval"


def test_finding_dict_includes_epss_percentile_when_cve_in_lookup():
    out = _finding_to_dict(
        make_finding(cve_id="CVE-2021-44228"),
        epss_lookup={"CVE-2021-44228": 0.97543},
    )
    assert out["epss_percentile"] == 0.97543


def test_finding_dict_epss_percentile_none_when_cve_absent_from_lookup():
    out = _finding_to_dict(
        make_finding(cve_id="CVE-9999-9999"),
        epss_lookup={"CVE-2021-44228": 0.5},
    )
    assert out["epss_percentile"] is None


def test_finding_dict_epss_percentile_none_when_finding_has_no_cve():
    out = _finding_to_dict(
        make_finding(cve_id=None),
        epss_lookup={"CVE-2021-44228": 0.5},
    )
    assert out["epss_percentile"] is None


def test_valid_sorts_includes_new_options():
    assert "severity_age" in VALID_SORTS
    assert "epss" in VALID_SORTS
    assert "cvss" in VALID_SORTS
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


def test_finding_dict_action_band_act_for_kev_critical():
    lookup = FakeKevLookup({"CVE-2021-44228"}, {})
    out = _finding_to_dict(make_finding(severity="critical"), kev_lookup=lookup)
    assert out["action_band"] == "act"


def test_finding_dict_action_band_track_for_no_signal_medium():
    lookup = FakeKevLookup(set(), {})
    out = _finding_to_dict(
        make_finding(severity="medium", cve_id=None, detail={}), kev_lookup=lookup
    )
    assert out["action_band"] == "track"


def test_finding_dict_surfaces_recommended_fix_from_detail():
    payload = {
        "packageName": "log4j-core",
        "fromVersion": "2.14.0",
        "toVersion": "2.17.1",
        "description": "Patch release — no API changes",
    }
    out = _finding_to_dict(make_finding(detail={"recommended_fix": payload}))
    assert out["recommended_fix"] == payload


def test_finding_dict_recommended_fix_none_when_detail_empty():
    out = _finding_to_dict(make_finding(detail={}))
    assert out["recommended_fix"] is None


def test_deps_title_uses_readable_package_slug_not_identity_key():
    out = _finding_to_dict(
        make_finding(
            tool="dependencies",
            title="ryt-action-ai::vllm::PyPI::GHSA-wr9h-g72x-mwhm::",
            identity_key="ryt-action-ai::vllm::PyPI::GHSA-wr9h-g72x-mwhm::",
            package_name="vllm",
            detail={"package_version": "0.7.3"},
        )
    )
    assert out["title"] == "vllm 0.7.3"


def test_deps_title_without_version_is_bare_package():
    out = _finding_to_dict(
        make_finding(tool="dependencies", title=None, package_name="vllm", detail={})
    )
    assert out["title"] == "vllm"


def test_non_package_finding_title_falls_back_to_title_then_cve():
    out = _finding_to_dict(
        make_finding(tool="iac_scanning", title="S3 bucket is public", package_name=None)
    )
    assert out["title"] == "S3 bucket is public"


# The deps/container lifecycle flattens the advisory into these top-level
# detail keys (no nested security_advisory dict is persisted).
_ADVISORY_FLAT_DETAIL = {
    "advisoryId": "GHSA-wr9h-g72x-mwhm",
    "cveId": "CVE-2025-59425",
    "cvssVector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "summary": "vLLM denial of service",
    "description": "A crafted request crashes the server.",
    "vulnerableVersionRange": ">= 0, < 0.11.0",
    "patchedVersion": "0.11.0",
    "publishedAt": "2025-09-01T00:00:00Z",
    "references": [
        {"url": "https://github.com/advisories/GHSA-wr9h-g72x-mwhm"},
        {"type": "WEB"},  # no url — dropped
    ],
}


def test_finding_advisory_surfaces_the_brief_from_flat_detail_keys():
    out = finding_advisory(
        make_finding(
            tool="dependencies",
            severity="high",
            package_name="vllm",
            detail=_ADVISORY_FLAT_DETAIL,
        )
    )
    assert out is not None
    assert out["advisory_id"] == "GHSA-wr9h-g72x-mwhm"
    assert out["cve_id"] == "CVE-2025-59425"
    assert out["severity"] == "high"
    assert out["cvss_vector"].startswith("CVSS:3.1/")
    assert out["summary"] == "vLLM denial of service"
    assert out["affected_range"] == ">= 0, < 0.11.0"
    assert out["fixed_version"] == "0.11.0"
    assert out["references"] == ["https://github.com/advisories/GHSA-wr9h-g72x-mwhm"]


def test_finding_advisory_none_when_no_advisory_keys():
    assert finding_advisory(make_finding(tool="code_scanning", detail={})) is None


def test_secret_verified_from_scanner_classification():
    history = [{"source": "scanner", "value": "verified_secret"}]
    assert _secret_verified({"classificationHistory": history}) is True
    history = [{"source": "scanner", "value": "uncertain"}]
    assert _secret_verified({"classificationHistory": history}) is False


def test_secret_verified_falls_back_to_raw_flag():
    assert _secret_verified({"raw": {"Verified": True}}) is True
    assert _secret_verified({"raw": {"Verified": False}}) is False


def test_secret_verified_none_when_unknown():
    assert _secret_verified({}) is None
    assert _secret_verified({"raw": {}}) is None


def test_finding_dict_exposes_secret_detector_and_validity():
    out = _finding_to_dict(
        make_finding(
            tool="secret_scanning",
            detail={
                "detector": "AWS",
                "classificationHistory": [{"source": "scanner", "value": "verified_secret"}],
            },
        )
    )
    assert out["secret_detector"] == "AWS secret"
    assert out["secret_verified"] is True


def test_finding_dict_secret_fields_none_for_non_secret():
    out = _finding_to_dict(make_finding(tool="dependencies", package_name="vllm", detail={}))
    assert out["secret_detector"] is None
    assert out["secret_verified"] is None


def test_finding_dict_exposes_introducing_commit():
    out = _finding_to_dict(
        make_finding(tool="secret_scanning", detail={"commit": "abc123def4567890"})
    )
    assert out["introduced_by_commit"] == "abc123def4567890"


def test_finding_dict_introducing_commit_none_when_absent():
    out = _finding_to_dict(make_finding(tool="dependencies", package_name="vllm", detail={}))
    assert out["introduced_by_commit"] is None


def test_finding_dict_exposes_container_image_context():
    out = _finding_to_dict(
        make_finding(
            tool="container_scanning",
            package_name="openssl",
            detail={
                "imageName": "acme/api",
                "imageTag": "1.4.2",
                "imageDigest": "sha256:abcd",
                "baseOs": "debian 12",
                "layerCount": "9",
                "layerDigest": "sha256:layer3",
                "layerIndex": "2",
            },
        )
    )
    img = out["container_image"]
    assert img == {
        "name": "acme/api",
        "tag": "1.4.2",
        "digest": "sha256:abcd",
        "base_os": "debian 12",
        "layer_count": 9,
        "layer_digest": "sha256:layer3",
        "layer_index": 2,
        "newer_tags": None,
    }


def test_finding_dict_container_image_none_for_non_container_or_missing_image():
    assert _finding_to_dict(make_finding(tool="dependencies", package_name="vllm", detail={}))[
        "container_image"
    ] is None
    assert _finding_to_dict(make_finding(tool="container_scanning", detail={}))[
        "container_image"
    ] is None


def test_finding_to_dict_hydrates_fat_code_window_for_detail_view(monkeypatch):
    import src.shared.finding_detail_blob as blob_mod

    # In production the code window lives in the fat blob, stripped from the
    # lean column — the detail view must hydrate to surface it.
    monkeypatch.setattr(
        blob_mod,
        "_load_fat_blob",
        lambda key: {"code_window": "def f():\n    eval(x)", "code_window_start_line": 10},
    )
    finding = make_finding(tool="code_scanning", detail={"startLine": 11, "endLine": 11})
    finding.detail_blob_key = "blob/key"
    out = _finding_to_dict(finding, hydrate=True)
    assert out["code_snippet"] is not None
    assert "eval" in out["code_snippet"]


def test_finding_to_dict_list_path_stays_lean_no_blob_read(monkeypatch):
    import src.shared.finding_detail_blob as blob_mod

    calls = {"n": 0}

    def _spy(key):
        calls["n"] += 1
        return {"code_window": "x"}

    monkeypatch.setattr(blob_mod, "_load_fat_blob", _spy)
    finding = make_finding(tool="code_scanning", detail={"startLine": 11})
    finding.detail_blob_key = "blob/key"
    out = _finding_to_dict(finding)  # hydrate defaults False
    assert calls["n"] == 0
    assert out["code_snippet"] is None


@pytest.mark.asyncio
async def test_advisory_intel_none_cve_returns_empty(db_session):
    out = await advisory_intel(None, db_session)
    assert out == {"epss_percentile": None, "kev": False, "kev_detail": None}


@pytest.mark.asyncio
async def test_advisory_intel_returns_epss_percentile_and_kev_detail(db_session):
    from datetime import date

    from src.db.models import EpssScore, KevEntry

    cve = "CVE-2099-0001"
    db_session.add(EpssScore(cve=cve, score=0.42, percentile=0.97, scored_date=date(2026, 6, 1)))
    db_session.add(
        KevEntry(
            cve_id=cve,
            due_date=date(2026, 7, 15),
            date_added=date(2026, 6, 24),
            known_ransomware_use=True,
        )
    )
    await db_session.commit()
    try:
        out = await advisory_intel(cve, db_session)
        assert out["epss_percentile"] == 0.97
        assert out["kev"] is True
        assert out["kev_detail"] == {
            "due_date": "2026-07-15",
            "date_added": "2026-06-24",
            "known_ransomware": True,
        }
    finally:
        await db_session.execute(delete(EpssScore).where(EpssScore.cve == cve))
        await db_session.execute(delete(KevEntry).where(KevEntry.cve_id == cve))
        await db_session.commit()


def test_finding_dict_surfaces_verification_reasoning():
    evidence = [
        {"file": "app/views.py", "line": 10, "snippet": "q = request.GET['q']", "kind": "source"},
        {"file": "app/db.py", "line": 42, "snippet": "cursor.execute(q)", "kind": "sink"},
    ]
    meta = {"model": "argus", "tokens_in": 1200, "tokens_out": 80}
    out = _finding_to_dict(
        make_finding(
            evidence=evidence,
            exploit_chain="Tainted query param flows into a raw SQL execute.",
            verification_metadata=meta,
            detail={"reachability": "reachable"},
        )
    )
    assert out["evidence"] == evidence
    assert out["exploit_chain"] == "Tainted query param flows into a raw SQL execute."
    assert out["verification_metadata"] == meta
    assert out["reachability"] == "reachable"


def test_finding_dict_verification_reasoning_none_when_unverified():
    out = _finding_to_dict(make_finding(detail={}))
    assert out["evidence"] is None
    assert out["exploit_chain"] is None
    assert out["verification_metadata"] is None
    assert out["reachability"] is None


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


def test_secret_finding_title_shows_detector_not_identity_hash():
    # Secret findings have no real title and a hash::repo identity key; the
    # public title must read as the secret type, never the leaked hash.
    finding = make_finding(
        tool="secret_scanning",
        title=None,
        identity_key="fdcbc1f7e9a0a0809ed791b68260ac9edfbf109ff8734c14d37334001bfe94d8::ryt-action-ai",
        detail={"detector": "AWS"},
    )
    out = _finding_to_dict(finding)
    assert out["title"] == "AWS secret"
    assert "::" not in out["title"]


def test_secret_finding_title_humanises_hyphenated_detector():
    finding = make_finding(
        tool="secret_scanning", title=None, detail={"detector": "github-pat"}
    )
    assert _finding_to_dict(finding)["title"] == "github pat secret"


def test_secret_finding_title_falls_back_when_detector_missing():
    finding = make_finding(
        tool="secret_scanning", title=None, identity_key="abc123::repo", detail={}
    )
    out = _finding_to_dict(finding)
    assert out["title"] == "Detected secret"
    assert "::" not in out["title"]


def test_secret_finding_detector_already_descriptive_not_doubled():
    finding = make_finding(
        tool="secret_scanning", title=None, detail={"detector": "Stripe API Key"}
    )
    assert _finding_to_dict(finding)["title"] == "Stripe API Key"


def test_code_snippet_exposed_for_sast():
    finding = make_finding(
        tool="code_scanning", detail={"snippet": "eval(user_input)"}
    )
    assert _finding_to_dict(finding)["code_snippet"] == "eval(user_input)"


def test_code_snippet_for_deps_uses_manifest_window():
    # Deps render through the same generic code-window path as code/iac: the
    # runner captures the manifest declaration line + a surrounding window.
    finding = make_finding(
        tool="dependencies_scanning",
        detail={
            "code_window": "log4j-core==2.14.0",
            "code_window_start_line": 12,
            "startLine": 12,
        },
    )
    assert _finding_to_dict(finding)["code_snippet"] == "log4j-core==2.14.0"


def test_secret_code_snippet_never_leaks_raw_value():
    # The raw secret lives in secretSnippet / raw.Secret; the preview must use
    # only the redacted match so a live credential never reaches the client.
    finding = make_finding(
        tool="secret_scanning",
        title=None,
        detail={
            "detector": "AWS",
            "secretSnippet": "AKIAIOSFODNN7EXAMPLE",
            "raw": {"Secret": "AKIAIOSFODNN7EXAMPLE", "Redacted": "AKIA****************"},
        },
    )
    snippet = _finding_to_dict(finding)["code_snippet"]
    assert snippet == "AKIA****************"
    assert "AKIAIOSFODNN7EXAMPLE" not in (snippet or "")


def test_secret_highlight_snaps_to_redaction_marker_when_reported_line_off():
    # git-history scans report a diff-relative line that can drift from the
    # file's current line. The window is anchored to real file lines, so the
    # highlight must snap to the line actually holding the secret (its marker),
    # not the reported line one row below it.
    finding = make_finding(
        tool="secret_scanning",
        title=None,
        detail={
            "code_window": "a = 1\nAPI_KEY = •••redacted-secret•••\nBACKEND = 2",
            "code_window_start_line": 14,
            "line": 16,  # scanner over-reports by one; the marker sits on line 15
            "raw": {},
        },
    )
    out = _finding_to_dict(finding)
    assert out["code_highlight_start"] == 15
    assert out["code_highlight_end"] == 15


def test_secret_highlight_stays_on_reported_line_when_marker_matches():
    # filesystem scans report accurate lines; the marker is on the reported
    # line, so the highlight must not move.
    finding = make_finding(
        tool="secret_scanning",
        title=None,
        detail={
            "code_window": "x\ngenai.configure(api_key=•••redacted-secret•••)\ny",
            "code_window_start_line": 73,
            "line": 74,
            "raw": {},
        },
    )
    assert _finding_to_dict(finding)["code_highlight_start"] == 74


def test_secret_highlight_locates_unmasked_raw_value_in_legacy_window():
    # Windows stored before the runner redacted still carry the raw value; the
    # highlight locates it (then the API re-masks it out of the snippet).
    finding = make_finding(
        tool="secret_scanning",
        title=None,
        detail={
            "code_window": "a\nb\ntoken = 'sk-live-abc'\nc",
            "code_window_start_line": 20,
            "line": 24,
            "raw": {"Raw": "sk-live-abc"},
        },
    )
    out = _finding_to_dict(finding)
    assert out["code_highlight_start"] == 22
    assert "sk-live-abc" not in (out["code_snippet"] or "")


def test_secret_highlight_falls_back_to_reported_line_without_a_hit():
    # No marker or raw value in the window (e.g. the file changed since a
    # history scan) — keep the reported line rather than mis-highlighting.
    finding = make_finding(
        tool="secret_scanning",
        title=None,
        detail={
            "code_window": "unrelated\ncode\nhere",
            "code_window_start_line": 40,
            "line": 41,
            "raw": {},
        },
    )
    assert _finding_to_dict(finding)["code_highlight_start"] == 41


def test_code_snippet_none_when_absent():
    assert _finding_to_dict(make_finding(detail={}))["code_snippet"] is None


def test_repo_html_url_emitted_from_detail():
    finding = make_finding(
        tool="code_scanning",
        detail={"repoHtmlUrl": "https://ghe.acme-corp.internal/acme/api"},
    )
    assert _finding_to_dict(finding)["repo_html_url"] == "https://ghe.acme-corp.internal/acme/api"


def test_repo_html_url_none_when_absent_or_blank():
    assert _finding_to_dict(make_finding(detail={}))["repo_html_url"] is None
    assert _finding_to_dict(make_finding(detail={"repoHtmlUrl": "  "}))["repo_html_url"] is None


def test_code_flows_exposed_when_present():
    flows = [
        {"file": "a.py", "line": 3, "snippet": "x = req.args['q']"},
        {"file": "a.py", "line": 9, "snippet": "db.execute(x)"},
    ]
    out = _finding_to_dict(make_finding(tool="code_scanning", detail={"code_flows": flows}))
    assert out["code_flows"] == flows
    assert _finding_to_dict(make_finding(detail={}))["code_flows"] is None


def test_code_window_anchored_and_highlighted():
    finding = make_finding(
        tool="code_scanning",
        detail={
            "code_window": "a\nb\nc\nd\ne",
            "code_window_start_line": 90,
            "startLine": 92,
            "endLine": 93,
        },
    )
    out = _finding_to_dict(finding)
    assert out["code_snippet"] == "a\nb\nc\nd\ne"
    assert out["code_snippet_start_line"] == 90
    assert out["code_highlight_start"] == 92
    assert out["code_highlight_end"] == 93


def test_code_window_start_line_derived_for_legacy_data():
    # Window stored before the runner emitted its start line: anchor it from the
    # finding line and the known context radius so highlighting still works.
    finding = make_finding(
        tool="code_scanning",
        detail={"code_window": "x\ny\nz", "startLine": 50},
    )
    out = _finding_to_dict(finding)
    assert out["code_snippet_start_line"] == 10  # max(1, 50 - 40)
    assert out["code_highlight_start"] == 50


def test_bare_snippet_highlights_itself_anchored_to_start_line():
    finding = make_finding(
        tool="code_scanning",
        detail={"snippet": "eval(x)", "startLine": 7},
    )
    out = _finding_to_dict(finding)
    assert out["code_snippet"] == "eval(x)"
    assert out["code_snippet_start_line"] == 7
    assert out["code_highlight_start"] == 7
    assert out["code_highlight_end"] == 7


def test_deps_preview_anchors_to_manifest_declaration_line():
    # Window starts at line 10; the declaration (startLine) is line 12 and is the
    # highlighted line — the offending dep shown in surrounding manifest context.
    finding = make_finding(
        tool="dependencies_scanning",
        detail={
            "code_window": '"deps": {\n  "a": "1"\n  "log4j-core": "2.14.0"',
            "code_window_start_line": 10,
            "startLine": 12,
        },
    )
    out = _finding_to_dict(finding)
    assert '"log4j-core": "2.14.0"' in out["code_snippet"]
    assert out["code_snippet_start_line"] == 10
    assert out["code_highlight_start"] == 12
    assert out["code_highlight_end"] == 12


def test_iac_finding_gets_anchored_highlighted_snippet():
    finding = make_finding(
        tool="iac_scanning",
        detail={"snippet": "resource aws_s3_bucket {}", "startLine": 5},
    )
    out = _finding_to_dict(finding)
    assert out["code_snippet"] == "resource aws_s3_bucket {}"
    assert out["code_snippet_start_line"] == 5
    assert out["code_highlight_start"] == 5


def test_secret_preview_has_no_line_anchoring():
    finding = make_finding(
        tool="secret_scanning",
        title=None,
        detail={"raw": {"Redacted": "AKIA****"}},
    )
    out = _finding_to_dict(finding)
    assert out["code_snippet"] == "AKIA****"
    assert out["code_snippet_start_line"] is None
    assert out["code_highlight_start"] is None


def test_sast_finding_surfaces_triage_fields():
    # An analyst needs the explanation, rule, weakness, and fix — all of which
    # live in detail and must reach the response.
    finding = make_finding(
        tool="code_scanning",
        title="repo:/workspace/job-abc/server.py:py.rule.id:93",
        cve_id=None,
        detail={
            "message": "Detected subprocess call with shell=True; this allows command injection.",
            "ruleName": "dangerous-subprocess-use",
            "cwe": ["CWE-78"],
            "confidence": "High",
            "fixSuggestion": "Pass args as a list and set shell=False.",
            "startLine": 93,
        },
    )
    out = _finding_to_dict(finding)
    # Title becomes the human message, not the leaked clone path.
    assert out["title"] == "Detected subprocess call with shell=True; this allows command injection."
    assert "/workspace/" not in out["title"]
    assert out["description"].startswith("Detected subprocess call")
    assert out["rule"] == "dangerous-subprocess-use"
    assert out["cwe"] == "CWE-78"
    assert out["confidence"] == "high"
    assert out["remediation"] == "Pass args as a list and set shell=False."
    assert out["line"] == 93


def test_sast_title_falls_back_to_rule_then_raw_title():
    by_rule = _finding_to_dict(make_finding(
        tool="code_scanning", title="leaked", detail={"ruleName": "sql-injection"}))
    assert by_rule["title"] == "sql-injection"


def test_triage_fields_absent_for_plain_finding():
    out = _finding_to_dict(make_finding(detail={}))
    assert out["description"] is None
    assert out["rule"] is None
    assert out["remediation"] is None
    assert out["confidence"] is None


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
        tool="dependencies_scanning",
        identity_key=f"key-{uuid4()}",
        state="open",
        severity="critical",
        title="log4j-core",
        detail={},
        asset_id=str(asset.id),
    )
    # user_a is granted access to the asset so it is a valid assignee; user_b is
    # left ungranted (assigning a finding to a user who can't see its asset is
    # rejected).
    grant = Grant(subject_type="user", subject_id=user_a.id, asset_id=str(asset.id))
    db_session.add_all([user_a, user_b, finding, grant])
    await db_session.commit()
    asset_ids = [str(asset.id)]
    yield finding, user_a, user_b, asset_ids
    await db_session.execute(
        delete(Grant).where(Grant.subject_id == user_a.id, Grant.asset_id == str(asset.id))
    )
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
async def test_assign_finding_rejects_user_without_asset_access(db_session, assign_finding_fixture):
    # user_b exists but holds no grant on the finding's asset — assigning to them
    # would leak the finding cross-scope, so it is rejected like an unknown user.
    finding, _, user_b, asset_ids = assign_finding_fixture
    with pytest.raises(ValueError, match="unknown user"):
        await assign_finding(finding.id, user_b.id, db_session, asset_ids)


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
async def test_list_assignable_users_returns_id_and_username_only(db_session, assignable_users_fixture):
    alice, _, _, suffix = assignable_users_fixture
    rows = await list_assignable_users(db_session, q=suffix, limit=5)
    assert all(set(r.keys()) == {"id", "username"} for r in rows)
    assert all("email" not in r for r in rows)


@pytest.mark.asyncio
async def test_list_assignable_users_restricts_to_allowed_ids(db_session, assignable_users_fixture):
    alice, bob, _, suffix = assignable_users_fixture
    rows = await list_assignable_users(
        db_session, q=suffix, limit=10, allowed_user_ids={alice.id}
    )
    ids = {r["id"] for r in rows}
    assert alice.id in ids
    assert bob.id not in ids


@pytest.mark.asyncio
async def test_list_assignable_users_empty_allowed_ids_returns_nothing(db_session, assignable_users_fixture):
    _, _, _, suffix = assignable_users_fixture
    rows = await list_assignable_users(
        db_session, q=suffix, limit=10, allowed_user_ids=set()
    )
    assert rows == []


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
        db_session, tool="dependencies_scanning", asset_id=asset_id,
        org="acme", repo="upsert-test",
        identity_key=f"ut-upsert-{uuid4()}", state="open", severity="high",
        detail={"title": "test"},
    )
    assert f.asset_id == asset_id


@pytest.mark.asyncio
async def test_upsert_finding_accepts_null_asset_id_for_secrets(db_session, _isolated_upsert_finding):
    from src.shared.finding_queries import upsert_finding

    f = await upsert_finding(
        db_session, tool="secret_scanning", asset_id=None,
        org="acme", repo=None,
        identity_key=f"ut-upsert-{uuid4()}", state="open", severity=None,
        detail={},
    )
    assert f.asset_id is None


@pytest.mark.asyncio
async def test_upsert_finding_promotes_recommended_fix_from_detail(
    db_session, _isolated_upsert_finding
):
    from src.shared.finding_queries import upsert_finding

    fix = {"kind": "rotation", "title": "Rotate the leaked AWS key"}
    f = await upsert_finding(
        db_session, tool="secret_scanning", asset_id=None,
        org="acme", repo=None,
        identity_key=f"ut-upsert-{uuid4()}", state="open", severity="high",
        detail={"recommended_fix": fix},
    )
    assert f.recommended_fix == fix


@pytest.mark.asyncio
async def test_upsert_finding_promotes_cvss_score_from_metadata(
    db_session, _isolated_upsert_finding
):
    from src.shared.finding_queries import upsert_finding

    f = await upsert_finding(
        db_session, tool="code_scanning", asset_id=None,
        org="acme", repo=None,
        identity_key=f"ut-cvss-{uuid4()}", state="open", severity="high",
        detail={"verification_metadata": {"cvss_score": 7.8}},
    )
    assert f.cvss_score == 7.8


@pytest.mark.asyncio
async def test_upsert_finding_cvss_score_none_when_absent(
    db_session, _isolated_upsert_finding
):
    from src.shared.finding_queries import upsert_finding

    f = await upsert_finding(
        db_session, tool="code_scanning", asset_id=None,
        org="acme", repo=None,
        identity_key=f"ut-nocvss-{uuid4()}", state="open", severity="high",
        detail={"verification_metadata": {"impact": "x"}},
    )
    assert f.cvss_score is None


# Verdict filter normalization

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


def test_normalize_filters_accepts_multi_repo_scope():
    out = _normalize_filters(
        FindingsListFilters(org_id="acme", repo=["github:acme/a", "github:acme/b"])
    )
    assert out.repo == ["github:acme/a", "github:acme/b"]


def test_normalize_filters_drops_blank_repos_and_caps_count():
    out = _normalize_filters(
        FindingsListFilters(org_id="acme", repo=["  github:acme/a  ", "", "  "] + [f"r{i}" for i in range(600)])
    )
    assert out.repo[0] == "github:acme/a"   # trimmed, blanks removed
    assert len(out.repo) == 500              # count capped


def test_deps_upgrade_fix_synthesizes_full_payload():
    finding = make_finding(
        tool="dependencies_scanning",
        package_name="lodash",
        detail={"patchedVersion": "4.17.21", "currentVersion": "4.17.10"},
    )
    out = _finding_to_dict(finding)
    assert out["recommended_fix"] == {
        "packageName": "lodash",
        "fromVersion": "4.17.10",
        "toVersion": "4.17.21",
    }


def test_deps_upgrade_fix_handles_dict_patched_version_shape():
    # Robustness: handle the raw {"identifier": "..."} shape in case it's
    # stored before the normalizer extracted the string.
    finding = make_finding(
        tool="dependencies_scanning",
        package_name="lodash",
        detail={
            "patchedVersion": {"identifier": "4.17.21"},
            "currentVersion": "4.17.10",
        },
    )
    out = _finding_to_dict(finding)
    assert out["recommended_fix"] is not None
    assert out["recommended_fix"]["toVersion"] == "4.17.21"


def test_deps_upgrade_fix_none_when_no_patched_version():
    finding = make_finding(
        tool="dependencies_scanning",
        package_name="lodash",
        detail={"currentVersion": "4.17.10"},
    )
    out = _finding_to_dict(finding)
    assert out["recommended_fix"] is None


def test_deps_upgrade_fix_skipped_for_non_deps_tool():
    finding = make_finding(
        tool="code_scanning",
        detail={"patchedVersion": "1.0.1"},
    )
    out = _finding_to_dict(finding)
    assert out["recommended_fix"] is None


def test_stored_recommended_fix_takes_precedence_over_synthesis():
    stored = {
        "packageName": "log4j-core",
        "fromVersion": "2.14.0",
        "toVersion": "2.17.1",
    }
    finding = make_finding(
        tool="dependencies_scanning",
        package_name="log4j-core",
        detail={
            "recommended_fix": stored,
            "patchedVersion": "2.15.0",
            "currentVersion": "2.14.0",
        },
    )
    out = _finding_to_dict(finding)
    assert out["recommended_fix"] == stored


def test_recommended_fix_column_serialized_for_non_deps_finding():
    fix = {"kind": "rotation", "title": "Rotate the leaked AWS key"}
    finding = make_finding(
        tool="secret_scanning",
        cve_id=None,
        package_name=None,
        recommended_fix=fix,
    )
    out = _finding_to_dict(finding)
    assert out["recommended_fix"] == fix


def test_recommended_fix_column_wins_over_deps_synthesis():
    fix = {"kind": "rotation", "title": "Rotate the leaked AWS key"}
    finding = make_finding(
        tool="dependencies_scanning",
        package_name="lodash",
        detail={"patchedVersion": "4.17.21", "currentVersion": "4.17.10"},
        recommended_fix=fix,
    )
    out = _finding_to_dict(finding)
    assert out["recommended_fix"] == fix


def test_has_fix_true_for_deps_synthesized_fix():
    from src.findings.resolvers import _row_from_dict
    finding = make_finding(
        tool="dependencies_scanning",
        package_name="lodash",
        detail={"patchedVersion": "4.17.21", "currentVersion": "4.17.10"},
    )
    row = _row_from_dict(_finding_to_dict(finding))
    assert row.has_fix is True


def test_has_fix_true_for_column_set_finding():
    from src.findings.resolvers import _row_from_dict
    finding = make_finding(
        tool="secret_scanning",
        cve_id=None,
        package_name=None,
        recommended_fix={"kind": "rotation", "title": "Rotate the leaked AWS key"},
    )
    row = _row_from_dict(_finding_to_dict(finding))
    assert row.has_fix is True


def test_has_fix_false_when_no_fix_available():
    from src.findings.resolvers import _row_from_dict
    finding = make_finding(
        tool="secret_scanning",
        cve_id=None,
        package_name=None,
        detail={},
    )
    row = _row_from_dict(_finding_to_dict(finding))
    assert row.has_fix is False


def test_ruled_out_reason_surfaced_on_list_row():
    from src.findings.resolvers import _row_from_dict
    finding = make_finding(
        verification_metadata={
            "ruled_out_reason": {
                "file": "app/lib/fetch.ts",
                "line": 42,
                "reasoning": "URL is validated against an allowlist before the fetch sink.",
            }
        },
    )
    finding.verdict = "ruled_out"
    row = _row_from_dict(_finding_to_dict(finding))
    assert row.ruled_out_reason == "URL is validated against an allowlist before the fetch sink."


def test_ruled_out_reason_none_for_non_ruled_out_verdict():
    from src.findings.resolvers import _row_from_dict
    # Same metadata shape, but a needs_verify verdict must not leak the reason —
    # a downgraded suppression writes ruled_out_reason yet is NOT ruled out.
    finding = make_finding(
        verification_metadata={"ruled_out_reason": {"reasoning": "unconfirmed mitigation"}},
    )
    finding.verdict = "needs_verify"
    row = _row_from_dict(_finding_to_dict(finding))
    assert row.ruled_out_reason is None


def test_cursor_predicate_returns_none_for_deferred_sorts():
    """A stray/stale cursor under a page-number sort must not inject a keyset
    clause keyed on the wrong column (it would silently scramble the page)."""
    from src.findings.service import _cursor_predicate

    payload = {"id": "00000000-0000-0000-0000-000000000001", "ts": "2026-01-01T00:00:00"}
    for sort in ("action_band", "risk_score", "severity_age", "epss", "newest", "oldest"):
        assert _cursor_predicate(payload, sort, "desc") is None
        assert _cursor_predicate(payload, sort, "asc") is None


def test_code_preview_secret_uses_redacted_window():
    from src.findings.service import _code_preview

    detail = {
        "raw": {"Raw": "leaked-value", "Redacted": "le...ue"},
        "code_window": "FOO=bar\nKEY=•••redacted-secret•••\nBAZ=qux",
        "code_window_start_line": 10,
        "line": 11,
    }
    preview = _code_preview("secret_scanning", detail)
    assert preview is not None
    assert "leaked-value" not in preview["text"]
    assert preview["start_line"] == 10
    assert preview["highlight_start"] == 11


def test_code_preview_secret_window_remasks_raw_value():
    """Defense in depth: even if the runner missed a value, the backend re-masks it."""
    from src.findings.service import _code_preview

    detail = {
        "raw": {"Raw": "still-here-secret"},
        "code_window": "A=1\nKEY=still-here-secret\nB=2",
        "code_window_start_line": 5,
        "line": 6,
    }
    preview = _code_preview("secret_scanning", detail)
    assert "still-here-secret" not in preview["text"]


def test_code_preview_secret_falls_back_to_redacted_match_without_window():
    from src.findings.service import _code_preview

    preview = _code_preview("secret_scanning", {"raw": {"Redacted": "AKIA...MPLE"}})
    assert preview["text"] == "AKIA...MPLE"
    assert preview["start_line"] is None


def test_code_preview_secret_masks_value_from_secret_field_in_window():
    """Detectors that carry the raw value in `Secret` (not Raw) must still mask."""
    from src.findings.service import _code_preview

    detail = {
        "raw": {"Secret": "sk-live-abc123", "Redacted": "sk-...23"},
        "code_window": "A=1\nKEY=sk-live-abc123\nB=2",
        "code_window_start_line": 5,
        "line": 6,
    }
    preview = _code_preview("secret_scanning", detail)
    assert "sk-live-abc123" not in preview["text"]


def test_code_preview_secret_masks_value_from_match_field_in_window():
    """Detectors that carry the raw value in `Match` must still mask."""
    from src.findings.service import _code_preview

    detail = {
        "raw": {"Match": "ghp_rawtoken999"},
        "code_window": "x\nTOKEN=ghp_rawtoken999\ny",
        "code_window_start_line": 1,
        "line": 2,
    }
    preview = _code_preview("secret_scanning", detail)
    assert "ghp_rawtoken999" not in preview["text"]


def test_code_preview_secret_no_window_never_leaks_raw_match():
    """Without a Redacted form, the no-window path must NOT fall back to the
    raw Match — for many detectors that field IS the plaintext secret."""
    from src.findings.service import _code_preview

    preview = _code_preview("secret_scanning", {"raw": {"Match": "sk-raw-plaintext"}})
    assert preview is None


def test_code_preview_secret_scrubs_unrelated_credential_in_context():
    """A different credential on a nearby line of the window is also masked."""
    from src.findings.service import _code_preview

    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.abcDEF123_signature-part"
    detail = {
        "raw": {"Secret": "sk-flagged-value-1234567890", "Redacted": "sk-...90"},
        "code_window": f"api_key=sk-flagged-value-1234567890\ntoken={jwt}\nport=8080",
        "code_window_start_line": 1,
        "line": 1,
    }
    preview = _code_preview("secret_scanning", detail)
    # Flagged value masked (precise) AND the unrelated JWT masked (context scrub).
    assert "sk-flagged-value-1234567890" not in preview["text"]
    assert jwt not in preview["text"]
    # Non-secret context is untouched.
    assert "port=8080" in preview["text"]


def test_scrub_known_secrets_leaves_ordinary_config_alone():
    from src.findings.service import _scrub_known_secrets

    text = "host=localhost\nport=5432\nname=my_app_db\nsize=sk-123"  # too short for sk- rule
    assert _scrub_known_secrets(text) == text


def _blast_asset(db_session, label):
    asset = Asset(
        type="repo",
        source="source_connection",
        external_ref=f"github:acme/{label}-{uuid4().hex[:8]}",
        display_name=f"acme/{label}",
    )
    db_session.add(asset)
    return asset


@pytest.mark.asyncio
async def test_count_related_repos_counts_other_active_assets_sharing_cve(db_session):
    cve = "CVE-2099-7777"
    assets = [_blast_asset(db_session, f"blast{i}") for i in range(3)]
    await db_session.flush()
    findings = [
        Finding(
            tool="dependencies_scanning",
            identity_key=f"k-{uuid4()}",
            state="open",
            severity="high",
            cve_id=cve,
            detail={},
            asset_id=str(a.id),
        )
        for a in assets
    ]
    # A fixed finding on a 4th asset must NOT count toward the blast radius.
    fixed_asset = _blast_asset(db_session, "blastfixed")
    await db_session.flush()
    fixed = Finding(
        tool="dependencies_scanning",
        identity_key=f"k-{uuid4()}",
        state="fixed",
        severity="high",
        cve_id=cve,
        detail={},
        asset_id=str(fixed_asset.id),
    )
    db_session.add_all([*findings, fixed])
    await db_session.commit()

    scope = [str(a.id) for a in assets] + [str(fixed_asset.id)]
    try:
        # From the first finding, the other two active assets are the blast radius.
        assert await count_related_repos(findings[0], scope, db_session) == 2
        # A finding with neither CVE nor package has no blast radius.
        no_match = make_finding(tool="code_scanning", cve_id=None, package_name=None)
        no_match.asset_id = str(assets[0].id)
        assert await count_related_repos(no_match, scope, db_session) == 0
        # Empty scope short-circuits to zero.
        assert await count_related_repos(findings[0], [], db_session) == 0

        # Drill-down: one row per other active repo (the fixed asset is excluded).
        related = await list_related_findings(findings[0], scope, db_session)
        assert len(related) == 2
        repos = {r["repo"] for r in related}
        assert repos == {assets[1].display_name, assets[2].display_name}
        assert all(r["severity"] == "high" and r["state"] == "open" for r in related)
        assert all(isinstance(r["finding_id"], str) for r in related)
        assert await list_related_findings(no_match, scope, db_session) == []
    finally:
        await db_session.execute(
            delete(Finding).where(Finding.id.in_([f.id for f in [*findings, fixed]]))
        )
        await db_session.execute(
            delete(Asset).where(Asset.id.in_([a.id for a in [*assets, fixed_asset]]))
        )
        await db_session.commit()
