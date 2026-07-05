from __future__ import annotations

import os
from datetime import date

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost:5432/test")
os.environ.setdefault("APP_SECRET", "0" * 64)

from src.releases import enrichment as enr  # noqa: E402
from src.releases.enrichment import (  # noqa: E402
    enrich_findings_with_release_age,
    maybe_enrich_release_age,
)
from src.releases.fetcher import system_for_ecosystem  # noqa: E402


class _FakeService:
    """In-memory stand-in for PackageReleaseDateService (no DB, no network)."""

    def __init__(self, cached=None):
        self.cached = cached or {}
        self.upserted: list[dict] = []

    def get_cached(self, coords):
        return {c: self.cached[c] for c in coords if c in self.cached}

    def upsert(self, rows):
        self.upserted.extend(rows)
        return len(rows)


def _finding(ecosystem: str, name: str, version: str) -> dict:
    return {
        "dependency": {"package": {"ecosystem": ecosystem, "name": name}},
        "current_version": version,
    }


def test_system_for_ecosystem_maps_supported_and_skips_rest():
    assert system_for_ecosystem("PyPI") == "pypi"
    assert system_for_ecosystem("crates.io") == "cargo"
    assert system_for_ecosystem("Go") == "go"
    assert system_for_ecosystem("Debian:12") is None
    assert system_for_ecosystem("RubyGems") is None
    assert system_for_ecosystem(None) is None


def test_enrich_stamps_age_and_recent_flag(monkeypatch):
    # npm/left-pad published 3 days before the scan; python/old 400 days before.
    monkeypatch.setattr(enr, "fetch_release_date", lambda s, n, v: {
        ("npm", "left-pad", "1.0.0"): date(2026, 1, 1),
        ("pypi", "old", "2.0.0"): date(2025, 1, 1),
    }.get((s, n, v)))
    findings = [
        _finding("npm", "left-pad", "1.0.0"),
        _finding("PyPI", "old", "2.0.0"),
        _finding("Debian:12", "openssl", "1.1"),  # unsupported → untouched
    ]
    svc = _FakeService()
    out = enrich_findings_with_release_age(
        findings, today=date(2026, 1, 4), threshold_days=90, service=svc
    )
    assert out[0]["release_age_days"] == 3
    assert out[0]["release_recent"] is True
    assert out[1]["release_age_days"] == 368
    assert out[1]["release_recent"] is False
    assert "release_age_days" not in out[2]  # distro ecosystem skipped
    # freshly fetched dates are written back to the cache
    assert len(svc.upserted) == 2


def test_enrich_uses_cache_and_skips_network(monkeypatch):
    def _boom(*a):
        raise AssertionError("should not hit the network on a cache hit")

    monkeypatch.setattr(enr, "fetch_release_date", _boom)
    svc = _FakeService(cached={("npm", "x", "1.0"): date(2026, 1, 1)})
    out = enrich_findings_with_release_age(
        [_finding("npm", "x", "1.0")], today=date(2026, 1, 11), threshold_days=5, service=svc
    )
    assert out[0]["release_age_days"] == 10
    assert out[0]["release_recent"] is False
    assert svc.upserted == []  # nothing new to cache


def test_maybe_enrich_is_noop_when_disabled(monkeypatch):
    monkeypatch.setattr(enr, "fetch_release_date", lambda *a: date(2026, 1, 1))
    findings = [_finding("npm", "x", "1.0")]
    out = maybe_enrich_release_age(findings, {"releaseAgeEnabled": "false"}, "acme")
    assert "release_age_days" not in out[0]


def test_release_age_flows_into_rules_subject():
    from src.shared.lifecycle import _build_subject_for_new_finding
    from src.rules_engine.subjects import get_finding_field
    from src.rules_engine.conditions import evaluate_condition

    subj = _build_subject_for_new_finding(
        tool="dependencies", severity="high", repo="acme/api",
        detail={"release_age_days": 2},
    )
    assert subj.release_age_days == 2
    cond = {"field": "release_age_days", "op": "lt", "value": 7}
    assert evaluate_condition(cond, subj, get_finding_field) is True
