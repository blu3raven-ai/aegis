"""Unit tests for the shared analytics builder — risk model + counts + distribution.

Locks in the P0 posture-analytics fixes:
- the risk score is a weighted-volume score (not a proportion), shared live and
  by the nightly snapshot;
- unknown-severity findings are bucketed (not dropped), and surface as an
  explicit "unrated" distribution slice so the wedges sum to 100%.
"""
from __future__ import annotations

from src.shared.analytics import (
    BAND_MULTIPLIER,
    build_analytics,
    finding_exposure_weight,
    get_counts,
    get_risk_score,
    get_severity_distribution,
    posture_risk_gauge,
    posture_risk_gauge_from_raw,
    posture_weighted_volume,
)


def _f(severity: str | None) -> dict:
    return {"security_advisory": {"severity": severity}}


def _fk(severity: str | None, *, kev: bool = False, reach: str | None = None) -> dict:
    return {"security_advisory": {"severity": severity}, "kev_listed": kev, "reachability": reach}


# ── Counts: unknown-severity findings are bucketed, not dropped ────────────

def test_counts_buckets_unknown_severity():
    alerts = [_f("critical"), _f("high"), _f(None), _f("bogus"), _f("")]
    c = get_counts(alerts)
    assert c.critical == 1
    assert c.high == 1
    assert c.unknown == 3   # None / "bogus" / "" all land in unknown
    assert c.total == 5


def test_counts_treats_severity_case_insensitively():
    c = get_counts([_f("CRITICAL"), _f("High"), _f("LOW")])
    assert c.critical == 1 and c.high == 1 and c.low == 1 and c.unknown == 0


# ── Distribution: an explicit unrated slice so wedges sum to ~100% ──────────

def test_distribution_includes_unrated_slice_when_unknowns_present():
    items = get_severity_distribution([_f("critical"), _f("high"), _f(None), _f(None)])
    by_sev = {i.severity: i for i in items}
    assert "unrated" in by_sev
    assert by_sev["unrated"].count == 2
    assert by_sev["unrated"].percentage == 50
    # No unrated wedge when there are no unknowns.
    assert "unrated" not in {i.severity for i in get_severity_distribution([_f("low")])}


# ── Risk score: weighted volume, shared with the nightly snapshot ───────────

def test_risk_score_is_weighted_volume_not_proportion():
    # Old proportion score: (1 critical / 1 total) * 100 = 100 "Severe".
    # A lone critical must NOT max the scale under the volume-weighted curve.
    score = get_risk_score([_f("critical")])
    assert score.score == 5  # raw 10 → 100*(1-e^-0.05)
    assert score.rating == "Low"

    # 50 criticals among 500 lows (raw 1000): real severe exposure, scores high
    # but is NOT pinned at 100 — the curve keeps headroom above it.
    big = [_f("critical")] * 50 + [_f("low")] * 500
    score_big = get_risk_score(big)
    assert score_big.score == 99
    assert score_big.rating == "Severe"


def test_posture_weighted_volume_is_raw_and_additive():
    # Raw additive weighted volume backs the per-scanner/dimension contribution
    # figures — it must NOT clamp, so a dominant group's true share is preserved.
    assert posture_weighted_volume(critical=0, high=0, medium=0, low=0) == 0
    assert posture_weighted_volume(critical=1, high=0, medium=0, low=0) == 10
    assert posture_weighted_volume(critical=0, high=1, medium=0, low=0) == 5
    assert posture_weighted_volume(critical=0, high=0, medium=1, low=0) == 2
    assert posture_weighted_volume(critical=0, high=0, medium=0, low=1) == 1
    assert posture_weighted_volume(critical=5, high=5, medium=5, low=5) == 90
    # Unbounded: 20 criticals stays 200, not clamped to 100.
    assert posture_weighted_volume(critical=20, high=0, medium=0, low=0) == 200


def test_risk_gauge_is_non_saturating_and_monotonic():
    # The headline gauge must keep discriminating where the clamped score pins:
    # a bigger backlog always scores strictly higher, moderate backlogs sit well
    # below 100, and it never flat-lines at the ceiling.
    assert posture_risk_gauge(critical=0, high=0, medium=0, low=0) == 0
    assert posture_risk_gauge(critical=1, high=0, medium=0, low=0) == 5    # raw 10
    assert posture_risk_gauge(critical=5, high=5, medium=5, low=5) == 36   # raw 90
    s20 = posture_risk_gauge(critical=20, high=0, medium=0, low=0)   # raw 200
    s100 = posture_risk_gauge(critical=100, high=0, medium=0, low=0)  # raw 1000
    assert s20 == 63
    assert s100 == 99
    assert s20 < s100 < 100


def test_risk_score_unaffected_by_unknown_severity():
    # Unknown-severity findings are real open exposure but carry no severity
    # weight, so they neither inflate nor deflate the score (they sit in
    # `total` for counts/distribution but not in the weighted sum).
    assert get_risk_score([_f("critical"), _f(None)]).score == 5
    assert get_risk_score([_f("critical")]).score == 5


def test_finding_exposure_weight_reuses_action_band():
    # No exploitability signal → severity weight unchanged (Track ×1.0).
    assert finding_exposure_weight("critical") == 10
    assert finding_exposure_weight("high") == 5
    # KEV-listed high/critical → Act.
    assert finding_exposure_weight("critical", kev_listed=True) == 10 * BAND_MULTIPLIER["act"]
    # KEV-listed but medium → Attend (not Act — Act needs high/critical).
    assert finding_exposure_weight("medium", kev_listed=True) == 2 * BAND_MULTIPLIER["attend"]
    # Reachable + high (no KEV) → Attend.
    assert finding_exposure_weight("high", reachability="reachable") == 5 * BAND_MULTIPLIER["attend"]
    # Unknown severity contributes nothing regardless of signals.
    assert finding_exposure_weight(None, kev_listed=True) == 0.0


def test_get_risk_score_absence_neutral_and_kev_raises():
    # Absence-neutral: no KEV/reachability → identical to severity-only gauge.
    sev_only = [_f("critical")] * 3
    base = get_risk_score(sev_only)
    assert base.score == posture_risk_gauge_from_raw(30)  # 3 × weight 10, all Track
    # The same findings, KEV-listed, must score strictly higher (Act ×2.5).
    raised = get_risk_score([_fk("critical", kev=True)] * 3)
    assert raised.score > base.score
    assert raised.score == posture_risk_gauge_from_raw(3 * 10 * BAND_MULTIPLIER["act"])


def test_risk_score_ratings_thresholds():
    assert get_risk_score([_f("critical")] * 30).rating == "Severe"     # raw 300 → 78
    assert get_risk_score([_f("critical")] * 20).rating == "High"       # raw 200 → 63
    assert get_risk_score([_f("critical")] * 10).rating == "Moderate"   # raw 100 → 39
    assert get_risk_score([_f("critical")] * 5).rating == "Low"        # raw 50  → 22


def test_build_analytics_carries_unknown_through_counts_and_distribution():
    payload = build_analytics(
        open_findings=[_f("critical"), _f(None)],
        fixed_findings=[],
        repos=[],
    )
    assert payload.counts.unknown == 1
    assert payload.counts.total == 2
    assert any(s.severity == "unrated" for s in payload.severityDistribution)
    assert payload.riskScore.score == 5  # gauge over raw 10 (1 critical)
