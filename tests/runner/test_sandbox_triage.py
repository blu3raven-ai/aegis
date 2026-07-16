"""Triage must be selective: only worth detonating when there's a runnable entry
AND a risk signal (skill bundle / static hit / obfuscated entry / oversized file).
A benign repo with a plain postinstall is left alone."""
from __future__ import annotations

from runner.sandbox.triage import triage_target


def test_no_entry_never_worth_detonating(tmp_path):
    r = triage_target(str(tmp_path), has_entry=False, static_hits=5)
    assert r.worth_detonating is False and "nothing to detonate" in r.summary


def test_entry_without_risk_is_not_detonated(tmp_path):
    # A plain setup entry and nothing suspicious → skip (don't run untrusted code).
    r = triage_target(str(tmp_path), has_entry=True)
    assert r.worth_detonating is False and "no risk signal" in r.summary


def test_skill_bundle_with_entry_is_detonated(tmp_path):
    (tmp_path / "SKILL.md").write_text("# a skill")
    r = triage_target(str(tmp_path), has_entry=True)
    assert r.worth_detonating is True
    assert any(s.kind == "skill_bundle" for s in r.risk_signals)


def test_static_hit_with_entry_is_detonated(tmp_path):
    r = triage_target(str(tmp_path), has_entry=True, static_hits=2)
    assert r.worth_detonating is True
    assert any(s.kind == "static_hit" for s in r.risk_signals)


def test_obfuscated_entry_is_detonated(tmp_path):
    r = triage_target(str(tmp_path), has_entry=True, entry_obfuscated=True)
    assert r.worth_detonating is True


def test_oversized_instruction_file_is_flagged(tmp_path):
    # The SkillCloak size-cap padding trick — a 22MB README.
    (tmp_path / "README.md").write_text("A" * 6_000_000)
    r = triage_target(str(tmp_path), has_entry=True)
    assert r.worth_detonating is True
    assert any(s.kind == "oversized_file" for s in r.risk_signals)


def test_normal_size_instruction_file_is_not_flagged(tmp_path):
    (tmp_path / "README.md").write_text("normal readme")
    r = triage_target(str(tmp_path), has_entry=True)
    assert not any(s.kind == "oversized_file" for s in r.signals)


def test_risk_signals_excludes_the_bare_entry():
    r = triage_target("/no/such/path", has_entry=True, static_hits=1)
    kinds = {s.kind for s in r.risk_signals}
    assert "runnable_entry" not in kinds and "static_hit" in kinds
