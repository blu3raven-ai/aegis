"""Replay-based evaluation harness for the LLM verifiers.

Runs a verifier over hand-labeled fixtures with a ``ReplayLlm`` (no live key)
and reports **paired** suppression metrics. FP-reduction is never reported
without its recall-loss counterpart: the failure mode to guard against is an
over-aggressive filter that mislabels a truly-exploitable finding as a false
positive and hides a real vulnerability.

The harness is verifier-agnostic: each fixture names its ``verifier``
(``deps`` | ``sast`` | ``iac``) and ``run_fixture`` dispatches to it. The
suppression predicate is the one thing that differs per verifier, because each
hides findings on a different signal:

- ``deps``: a grounded ``no_path`` reachability (the citation-grounding rule
  downgrades an ungrounded one to ``unknown`` before it can hide anything).
- ``sast`` / ``iac``: a ``ruled_out`` verdict (the hunter found an exploit
  chain, the skeptic found a grounded mitigation that neutralises it).

Both reduce to the same abstract ``{truly_reachable, suppressed}`` shape that
``compute_metrics`` scores, so the paired recall-safety invariant —
``recall_loss == 0`` on the labeled set — holds across all verifiers.
"""
from __future__ import annotations

import json
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from runner.verification.evals.replay import ReplayLlm
from runner.verification.pipeline import verify_finding
from runner.verification.verifiers.deps import verify_deps_finding
from runner.verification.verifiers.iac import verify_iac_finding

_FIXTURES_DIR = Path(__file__).parent / "fixtures"


def _no_advisory(_ids: list[str]) -> dict:
    """Advisory-enrichment stub — fixtures stay hermetic and never hit the network."""
    return {}


@dataclass
class Fixture:
    """One hand-labeled eval case."""

    id: str
    verifier: str
    finding: dict
    repo_files: dict
    llm_responses: list
    expected: dict
    label: dict
    raw: dict = field(default_factory=dict)

    @property
    def truly_reachable(self) -> bool:
        """Ground truth: is the vulnerable code actually exploitable/reachable?"""
        return bool(self.label.get("truly_reachable"))


def load_fixtures(directory: str | Path = _FIXTURES_DIR) -> list[Fixture]:
    """Load every ``*.json`` fixture from ``directory``, sorted by filename."""
    root = Path(directory)
    fixtures: list[Fixture] = []
    for path in sorted(root.glob("*.json")):
        data = json.loads(path.read_text(encoding="utf-8"))
        fixtures.append(
            Fixture(
                id=data["id"],
                verifier=data["verifier"],
                finding=data["finding"],
                repo_files=data.get("repo_files", {}),
                llm_responses=data.get("llm_responses", []),
                expected=data.get("expected", {}),
                label=data.get("label", {}),
                raw=data,
            )
        )
    return fixtures


def _materialize(root: Path, repo_files: dict) -> None:
    """Write ``{path: content}`` into ``root``, creating parent directories."""
    for rel, content in repo_files.items():
        dest = root / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(content, encoding="utf-8")


def _is_suppressed_deps(reachability: str, evidence: list[dict]) -> bool:
    """Mirror the backend hide rule for deps: a ``no_path`` suppresses only when grounded.

    Grounded == at least one evidence item carries a real ``file`` citation.
    An ungrounded ``no_path`` is already downgraded to ``unknown`` upstream, so
    a surviving ``no_path`` here is grounded by construction; this predicate is
    the explicit, testable statement of that rule.
    """
    if reachability != "no_path":
        return False
    return any(isinstance(e, dict) and e.get("file") for e in (evidence or []))


def _is_suppressed_verdict(verdict: str) -> bool:
    """Mirror the backend hide rule for sast/iac: a ``ruled_out`` verdict hides.

    Every other verdict (``confirmed`` / ``needs_verify`` / ``possible``) keeps
    the finding visible. ``ruled_out`` is only reached when the skeptic found a
    *grounded* mitigation, so it is grounded by construction — the verifier's
    own citation critic downgrades an ungrounded mitigation to ``needs_verify``
    before it can hide anything.
    """
    return verdict == "ruled_out"


# Each verifier plugs in here: how to run it on a materialized repo, and how to
# derive (primary signal, suppressed) from its result. ``run`` returns the raw
# ``VerificationResult`` so the suppressor can read whichever fields it needs.
@dataclass(frozen=True)
class _VerifierAdapter:
    run: Callable[[dict, str, ReplayLlm], Any]
    suppressor: Callable[[Any], tuple[str, bool]]


def _run_deps(finding: dict, repo_root: str, llm: ReplayLlm):
    return verify_deps_finding(
        finding=finding, repo_root=repo_root, llm=llm, advisory_tool=_no_advisory,
    )


def _deps_suppressor(result) -> tuple[str, bool]:
    reachability = result.verification_metadata.get("reachability", "unknown")
    return reachability, _is_suppressed_deps(reachability, result.evidence)


def _run_sast(finding: dict, repo_root: str, llm: ReplayLlm):
    return verify_finding(finding=finding, repo_root=repo_root, llm=llm)


def _verdict_suppressor(result) -> tuple[str, bool]:
    return result.verdict, _is_suppressed_verdict(result.verdict)


def _run_iac(finding: dict, repo_root: str, llm: ReplayLlm):
    return verify_iac_finding(finding=finding, repo_root=repo_root, llm=llm)


_ADAPTERS: dict[str, _VerifierAdapter] = {
    "deps": _VerifierAdapter(run=_run_deps, suppressor=_deps_suppressor),
    "sast": _VerifierAdapter(run=_run_sast, suppressor=_verdict_suppressor),
    "iac": _VerifierAdapter(run=_run_iac, suppressor=_verdict_suppressor),
}


def run_fixture(fx: Fixture) -> dict:
    """Materialize the fixture repo, replay its responses, run the verifier."""
    adapter = _ADAPTERS.get(fx.verifier)
    if adapter is None:
        raise ValueError(
            f"unsupported verifier {fx.verifier!r}; supported: {sorted(_ADAPTERS)}"
        )

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        _materialize(root, fx.repo_files)
        llm = ReplayLlm(fx.llm_responses)
        result = adapter.run(fx.finding, str(root), llm)
        calls = llm.calls

    signal, suppressed = adapter.suppressor(result)
    # ``reachability`` is the deps-specific signal name; keep it as an alias so
    # deps fixtures read naturally and existing assertions keep working.
    expected_signal = fx.expected.get("signal", fx.expected.get("reachability"))
    out: dict = {
        "id": fx.id,
        "verifier": fx.verifier,
        "signal": signal,
        "suppressed": suppressed,
        "truly_reachable": fx.truly_reachable,
        "expected": fx.expected,
        "matches_expected": (
            signal == expected_signal
            and suppressed == bool(fx.expected.get("suppressed"))
        ),
        "llm_calls": calls,
    }
    if fx.verifier == "deps":
        out["reachability"] = signal
    return out


def compute_metrics(results: list[dict]) -> dict:
    """Paired suppression metrics over the labeled set.

    The positive class of the suppression decision is "should be hidden" ==
    truly non-reachable / non-exploitable. Definitions:

    - ``precision``: of the findings we hid, the fraction that were genuinely
      non-reachable (1.0 == no real vuln was ever hidden).
    - ``recall``: of the findings that *should* be hidden, the fraction we hid.
    - ``fp_reduction``: fraction of truly-non-reachable findings correctly hidden
      (recall restricted to the false-positive population).
    - ``recall_loss``: fraction of truly-reachable findings WRONGLY hidden — the
      number that must stay 0. A report omitting it is the anti-pattern.
    """
    tp = fp = fn = 0
    reachable_total = reachable_hidden = 0
    nonreachable_total = nonreachable_hidden = 0

    for r in results:
        should_hide = not r["truly_reachable"]
        suppressed = bool(r["suppressed"])
        if should_hide:
            nonreachable_total += 1
            if suppressed:
                tp += 1
                nonreachable_hidden += 1
            else:
                fn += 1
        else:
            reachable_total += 1
            if suppressed:
                fp += 1
                reachable_hidden += 1

    precision = tp / (tp + fp) if (tp + fp) else 1.0
    recall = tp / (tp + fn) if (tp + fn) else 1.0
    fp_reduction = nonreachable_hidden / nonreachable_total if nonreachable_total else 0.0
    recall_loss = reachable_hidden / reachable_total if reachable_total else 0.0

    return {
        "precision": precision,
        "recall": recall,
        "fp_reduction": fp_reduction,
        "recall_loss": recall_loss,
        "n": len(results),
        "suppressed": tp + fp,
        "truly_reachable": reachable_total,
        "truly_non_reachable": nonreachable_total,
    }


def run_eval(directory: str | Path = _FIXTURES_DIR) -> dict[str, Any]:
    """Load, run, and score every fixture under ``directory``."""
    fixtures = load_fixtures(directory)
    results = [run_fixture(fx) for fx in fixtures]
    return {"metrics": compute_metrics(results), "per_fixture": results}


def _main() -> None:
    print(json.dumps(run_eval(), indent=2, sort_keys=True))


if __name__ == "__main__":
    _main()
