"""Decide whether a target is worth detonating, from cheap static signals.

Detonation runs untrusted code, so we don't run it for every repo — a fast triage
decides. This keeps detonation SELECTIVE (only the targets a signal flags) rather
than all-or-nothing, and lets the same signals drive a 'recommend detonation'
finding when detonation is off, so operators see what warrants runtime analysis
without us executing anything.

A target is worth detonating only when it has a runnable entry AND at least one
risk signal: it's an agent-skill bundle (the SkillCloak surface — a skill that
phones home is malicious regardless of how cleanly it's packed), a static detector
already fired on it, the entry is obfuscated, or an instruction file is oversized
(the size-cap-padding evasion). A benign repo that merely has a postinstall is not
detonated.

Known residual (accepted trade-off): a repo whose setup entry looks clean —
no skill markers, no static hit, not obfuscated, no oversized file — but fetches
its payload only at runtime from an innocuous-looking host will NOT be detonated.
Detonating every repo with a setup entry is the all-or-nothing cost we avoid; the
mitigations are that the static detectors flag a malicious script's tell-tale
strings (→ static_hit → detonate) and that DETONATE-off still emits a low-severity
recommendation. Closing the residual fully would need runtime analysis of every
setup entry, which the opt-in design deliberately doesn't do.

Note: a 'high-entropy blob in .git/' signal was considered and rejected — git
objects are legitimately compressed and high-entropy, so it fires on every repo.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

# Instruction files an oversize check applies to (SkillCloak padded a README to
# 22 MB to slip under scanner size caps).
_INSTRUCTION_FILES = (
    "README.md", "SKILL.md", "AGENTS.md", "GEMINI.md", "CLAUDE.md",
    ".cursorrules", "copilot-instructions.md",
)
_OVERSIZED_BYTES = 5_000_000  # a 5MB+ instruction file is padding, not prose
# Presence of any of these means the repo is an agent-skill bundle.
_SKILL_MARKERS = ("SKILL.md", ".claude/skills", ".mcp.json")


@dataclass(frozen=True)
class TriageSignal:
    kind: str  # runnable_entry | skill_bundle | static_hit | obfuscated_entry | oversized_file
    detail: str


@dataclass(frozen=True)
class TriageResult:
    worth_detonating: bool
    signals: list[TriageSignal] = field(default_factory=list)
    summary: str = ""

    @property
    def risk_signals(self) -> list[TriageSignal]:
        """The signals (excluding the bare runnable-entry precondition) that make
        this target worth a closer look — the evidence for a recommendation."""
        return [s for s in self.signals if s.kind != "runnable_entry"]


def _is_skill_bundle(root: Path) -> bool:
    return any((root / m).exists() for m in _SKILL_MARKERS)


def _oversized_instruction_files(root: Path) -> list[TriageSignal]:
    out: list[TriageSignal] = []
    for name in _INSTRUCTION_FILES:
        p = root / name
        try:
            if p.is_file() and p.stat().st_size >= _OVERSIZED_BYTES:
                out.append(TriageSignal("oversized_file", f"{name} is {p.stat().st_size} bytes"))
        except OSError:
            continue
    return out


def triage_target(
    repo_root: str, *, has_entry: bool, entry_obfuscated: bool = False, static_hits: int = 0,
) -> TriageResult:
    """Score detonation-worthiness. Worth detonating iff there's something runnable
    AND a risk signal; benign setup entries are left alone."""
    root = Path(repo_root)
    signals: list[TriageSignal] = []
    if has_entry:
        signals.append(TriageSignal("runnable_entry", "setup entry present"))
    if _is_skill_bundle(root):
        signals.append(TriageSignal("skill_bundle", "agent-skill bundle"))
    if entry_obfuscated:
        signals.append(TriageSignal("obfuscated_entry", "setup entry is obfuscated"))
    if static_hits > 0:
        signals.append(TriageSignal("static_hit", f"{static_hits} static detector hit(s)"))
    signals.extend(_oversized_instruction_files(root))

    risk = any(s.kind in ("skill_bundle", "obfuscated_entry", "static_hit", "oversized_file") for s in signals)
    worth = has_entry and risk
    if worth:
        why = ", ".join(s.detail for s in signals if s.kind != "runnable_entry")
        summary = f"detonation recommended: runnable entry + {why}"
    elif has_entry:
        summary = "runnable entry but no risk signal — not detonating"
    else:
        summary = "no runnable entry — nothing to detonate"
    return TriageResult(worth_detonating=worth, signals=signals, summary=summary)
