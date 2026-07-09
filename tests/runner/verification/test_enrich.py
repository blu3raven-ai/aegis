"""stash_confirmed_enrichment copies audit-report fields into metadata."""
from types import SimpleNamespace

from runner.verification.enrich import stash_confirmed_enrichment


def _model(**kw):
    return SimpleNamespace(
        reproduction=kw.get("reproduction", ""),
        attack_paths=kw.get("attack_paths", []),
        mitigating_factors=kw.get("mitigating_factors", []),
    )


def test_copies_all_three_fields():
    meta = {}
    stash_confirmed_enrichment(meta, _model(
        reproduction="POST /x",
        attack_paths=[{"name": "A", "steps": "reach [R1]"}],
        mitigating_factors=["localhost only"],
    ))
    assert meta["reproduction"] == "POST /x"
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
