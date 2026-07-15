"""Contract tests for the generic finding merge engine.

merge_findings is shared by SCA and container matching: it dedups by a
caller-supplied key and, for collisions, prefers a fix version, the higher CVSS,
and the longer description, then runs a tool-specific merge hook. The survivor is
the first-seen finding, mutated in place.
"""
from __future__ import annotations

from src.shared.finding_merger import merge_findings


def _key(f):
    return f["k"]


def _cvss(f):
    return ((f.get("security_advisory") or {}).get("cvss") or {}).get("score") or 0


def _adv(k, *, score=0.0, desc="", summary="", fix=None):
    f = {"k": k, "security_advisory": {"cvss": {"score": score}, "description": desc, "summary": summary}}
    if fix is not None:
        f["security_vulnerability"] = {"first_patched_version": fix}
    return f


def test_empty_and_distinct_keys():
    assert merge_findings([], _key, _cvss) == []
    out = merge_findings([_adv("a"), _adv("b")], _key, _cvss)
    assert {f["k"] for f in out} == {"a", "b"}


def test_survivor_is_first_seen_object():
    first = _adv("a")
    out = merge_findings([first, _adv("a")], _key, _cvss)
    assert len(out) == 1
    assert out[0] is first  # mutated in place, identity preserved


def test_prefers_fix_version_when_survivor_lacks_one():
    out = merge_findings([_adv("a"), _adv("a", fix="1.2.3")], _key, _cvss)
    assert out[0]["security_vulnerability"]["first_patched_version"] == "1.2.3"


def test_does_not_overwrite_existing_fix_version():
    out = merge_findings([_adv("a", fix="1.0"), _adv("a", fix="2.0")], _key, _cvss)
    assert out[0]["security_vulnerability"]["first_patched_version"] == "1.0"


def test_prefers_higher_cvss():
    out = merge_findings([_adv("a", score=5.0), _adv("a", score=9.0)], _key, _cvss)
    assert _cvss(out[0]) == 9.0
    # Lower second value must not lower the survivor.
    out2 = merge_findings([_adv("a", score=9.0), _adv("a", score=5.0)], _key, _cvss)
    assert _cvss(out2[0]) == 9.0


def test_prefers_longer_description_and_syncs_summary():
    out = merge_findings(
        [_adv("a", desc="short", summary="s1"), _adv("a", desc="a much longer description", summary="s2")],
        _key, _cvss,
    )
    assert out[0]["security_advisory"]["description"] == "a much longer description"
    assert out[0]["security_advisory"]["summary"] == "s2"
    # Shorter second description leaves the survivor untouched.
    out2 = merge_findings([_adv("a", desc="longer original"), _adv("a", desc="tiny")], _key, _cvss)
    assert out2[0]["security_advisory"]["description"] == "longer original"


def test_merge_extra_runs_per_duplicate_only():
    calls = {"n": 0}

    def merge_extra(existing, new):
        calls["n"] += 1
        existing["sources"] = sorted(set(existing.get("sources", [])) | set(new.get("sources", [])))

    findings = [
        {**_adv("a"), "sources": ["osv"]},
        {**_adv("a"), "sources": ["ghsa"]},
        {**_adv("b"), "sources": ["osv"]},  # unique key -> hook not called
    ]
    out = merge_findings(findings, _key, _cvss, merge_extra)
    assert calls["n"] == 1  # only the one duplicate
    survivor = next(f for f in out if f["k"] == "a")
    assert survivor["sources"] == ["ghsa", "osv"]


def test_longer_desc_when_survivor_has_no_security_advisory():
    # Survivor lacks security_advisory entirely; a longer-description duplicate
    # must not crash — the block creates the dict (consistent with the CVSS branch).
    survivor = {"k": "a"}
    out = merge_findings([survivor, _adv("a", desc="has a description")], _key, _cvss)
    assert out[0]["security_advisory"]["description"] == "has a description"
