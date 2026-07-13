"""stash_confirmed_enrichment copies audit-report fields into metadata."""
from types import SimpleNamespace

from runner.verification.enrich import stash_confirmed_enrichment


def _model(**kw):
    return SimpleNamespace(
        title=kw.get("title", ""),
        impact=kw.get("impact", ""),
        reproduction=kw.get("reproduction", ""),
        fix=kw.get("fix", ""),
        attack_paths=kw.get("attack_paths", []),
        mitigating_factors=kw.get("mitigating_factors", []),
    )


def test_copies_all_three_fields():
    meta = {}
    stash_confirmed_enrichment(meta, _model(
        title="SSRF via header",
        impact="reads cloud metadata",
        reproduction="POST /x",
        fix="--- a/x\n+++ b/x",
        attack_paths=[{"name": "A", "steps": "reach [R1]"}],
        mitigating_factors=["localhost only"],
    ))
    assert meta["title"] == "SSRF via header"
    assert meta["impact"] == "reads cloud metadata"
    assert meta["reproduction"] == "POST /x"
    assert meta["fix"].startswith("--- a/x")
    assert meta["attack_paths"] == [{"name": "A", "steps": "reach [R1]"}]
    assert meta["mitigating_factors"] == ["localhost only"]


def test_drops_empty_and_malformed():
    meta = {}
    stash_confirmed_enrichment(meta, _model(
        reproduction="   ",
        attack_paths=[{"name": "A", "steps": ""}, "not-a-dict"],
        mitigating_factors=["", "  "],
    ))
    assert meta == {}  # nothing worth surfacing


def _hunter(**kw):
    base = dict(
        title="", impact="", reproduction="", attack_paths=[],
        mitigating_factors=[], fix="", cvss_metrics={}, distinctness="",
        remediation=[], poc_script="", poc_filename="", poc_language="",
    )
    base.update(kw)
    return SimpleNamespace(**base)


def test_valid_cvss_metrics_compute_vector_and_score():
    meta: dict = {}
    stash_confirmed_enrichment(meta, _hunter(cvss_metrics={
        "AV": "L", "AC": "L", "PR": "N", "UI": "R",
        "S": "U", "C": "H", "I": "H", "A": "H"}))
    assert meta["cvss_vector"] == "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"
    assert meta["cvss_score"] == 7.8
    assert meta["cvss_metrics"]["AV"] == "L"


def test_partial_cvss_metrics_dropped():
    meta: dict = {}
    stash_confirmed_enrichment(meta, _hunter(cvss_metrics={"AV": "L"}))
    assert "cvss_vector" not in meta
    assert "cvss_score" not in meta
    assert "cvss_metrics" not in meta


def test_distinctness_and_remediation_stashed():
    meta: dict = {}
    stash_confirmed_enrichment(meta, _hunter(
        distinctness="Different sink than CVE-2026-1.",
        remediation=["Use JSON.", " ", "Gate behind a flag."],
    ))
    assert meta["distinctness"] == "Different sink than CVE-2026-1."
    assert meta["remediation"] == ["Use JSON.", "Gate behind a flag."]


def test_poc_stashed_only_when_script_present():
    meta: dict = {}
    stash_confirmed_enrichment(meta, _hunter(
        poc_script="print('pwned')", poc_filename="poc.py", poc_language="python"))
    assert meta["poc_script"] == "print('pwned')"
    assert meta["poc_filename"] == "poc.py"
    assert meta["poc_language"] == "python"

    empty: dict = {}
    stash_confirmed_enrichment(empty, _hunter(poc_script="   "))
    assert "poc_script" not in empty
