"""Tests for the replay-based deps-verification eval harness.

The teeth of the harness: on the labeled corpus the pipeline must never hide a
truly-reachable finding (``recall_loss == 0``), and any FP-reduction number must
be reported alongside that recall-loss figure so the two can never be decoupled.
"""
from __future__ import annotations

import pytest

from runner.verification.evals.harness import (
    compute_metrics,
    load_fixtures,
    run_eval,
    run_fixture,
)
from runner.verification.evals.replay import ReplayError, ReplayLlm
from runner.verification.llm_client import LlmResponse


def test_run_eval_returns_metrics_over_bundled_fixtures():
    report = run_eval()

    assert report["metrics"]["n"] == len(report["per_fixture"]) > 0
    valid_signals = {
        # deps reachability tri-state
        "reachable", "no_path", "unknown",
        # sast / iac verdicts
        "confirmed", "needs_verify", "possible", "ruled_out",
    }
    for value in report["per_fixture"]:
        assert value["signal"] in valid_signals, value
        assert isinstance(value["suppressed"], bool)


def test_every_fixture_matches_its_expected_behavior():
    # Guards the fixtures themselves against silent drift in the verifier.
    for value in run_eval()["per_fixture"]:
        assert value["matches_expected"], value


def test_recall_loss_is_zero_on_labeled_set():
    # The pipeline must never suppress a truly-reachable finding.
    assert run_eval()["metrics"]["recall_loss"] == 0.0


def test_metrics_always_pair_fp_reduction_with_recall_loss():
    metrics = run_eval()["metrics"]
    assert "fp_reduction" in metrics
    assert "recall_loss" in metrics
    for required in ("precision", "recall", "fp_reduction", "recall_loss"):
        assert required in metrics


def test_recall_loss_would_flag_a_wrongful_suppression():
    # Sanity-check the metric has teeth: a hidden truly-reachable finding lifts it.
    bad = [{"truly_reachable": True, "suppressed": True}]
    assert compute_metrics(bad)["recall_loss"] == 1.0


def test_grounded_no_path_suppresses_but_ungrounded_does_not():
    by_id = {r["id"]: r for r in run_eval()["per_fixture"]}
    assert by_id["c_grounded_no_path_suppressed"]["suppressed"] is True
    assert by_id["d_ungrounded_no_path_downgraded"]["suppressed"] is False
    assert by_id["d_ungrounded_no_path_downgraded"]["reachability"] == "unknown"


def test_prefilter_case_spends_no_llm_call():
    by_id = {fx.id: fx for fx in load_fixtures()}
    result = run_fixture(by_id["b_not_imported_prefilter"])
    assert result["llm_calls"] == 0
    assert result["reachability"] == "no_path"


def test_replay_returns_responses_in_recorded_order():
    llm = ReplayLlm([
        {"content": "first"},
        {"content": "second", "tokens_in": 3, "tokens_out": 4},
    ])

    first = llm.chat([{"role": "user", "content": "x"}])
    second = llm.chat([{"role": "user", "content": "y"}])

    assert isinstance(first, LlmResponse)
    assert first.content == "first"
    assert second.content == "second"
    assert (second.tokens_in, second.tokens_out) == (3, 4)
    assert llm.calls == 2


def test_replay_under_supply_raises():
    llm = ReplayLlm([{"content": "only"}])
    llm.chat([{"role": "user", "content": "x"}])
    with pytest.raises(ReplayError):
        llm.chat([{"role": "user", "content": "y"}])


# ---------------------------------------------------------------------------
# Multi-verifier dispatch (sast + iac) and cross-verifier recall safety.
# ---------------------------------------------------------------------------

def test_replay_chat_json_replays_one_response_per_call():
    """chat_json pops one queued response per attempt; a valid response costs one."""
    from runner.verification.schemas.verdict import HunterResponse

    llm = ReplayLlm([
        {"content": '{"exploit_chain":"x","evidence":[]}'},
        {"content": '{"exploit_chain":"y","evidence":[]}'},
    ])
    first = llm.chat_json([{"role": "user", "content": "x"}], HunterResponse)
    second = llm.chat_json([{"role": "user", "content": "y"}], HunterResponse)
    assert first.parsed.exploit_chain == "x"
    assert second.parsed.exploit_chain == "y"
    assert llm.calls == 2


def test_replay_chat_json_returns_parsed_none_on_schema_failure():
    """Exhausting the repair budget surfaces parsed=None so the verifier falls back."""
    from runner.verification.schemas.verdict import HunterResponse

    llm = ReplayLlm([{"content": "not json"}, {"content": "still not json"}])
    result = llm.chat_json([{"role": "user", "content": "x"}], HunterResponse)
    assert result.parsed is None
    assert result.error
    assert llm.calls == 2  # one call + one repair attempt


def test_replay_chat_json_repairs_then_succeeds():
    """A bad-then-good pair recovers the parsed verdict on the second pop."""
    from runner.verification.schemas.verdict import HunterResponse

    llm = ReplayLlm([
        {"content": "not json"},
        {"content": '{"exploit_chain":"recovered","evidence":[]}'},
    ])
    result = llm.chat_json([{"role": "user", "content": "x"}], HunterResponse)
    assert result.parsed.exploit_chain == "recovered"
    assert llm.calls == 2


def test_harness_dispatches_to_sast_verifier():
    by_id = {r["id"]: r for r in run_eval()["per_fixture"]}
    sast = by_id["f_sast_confirmed"]
    assert sast["verifier"] == "sast"
    assert sast["signal"] == "confirmed"
    assert sast["suppressed"] is False
    # hunter + skeptic = 2 LLM calls.
    assert sast["llm_calls"] == 2


def test_harness_dispatches_to_iac_verifier():
    by_id = {r["id"]: r for r in run_eval()["per_fixture"]}
    iac = by_id["j_iac_confirmed"]
    assert iac["verifier"] == "iac"
    assert iac["signal"] == "confirmed"
    assert iac["suppressed"] is False
    assert iac["llm_calls"] == 2


def test_recall_loss_is_zero_across_all_verifiers():
    """No truly-reachable finding is hidden across deps + sast + iac."""
    assert run_eval()["metrics"]["recall_loss"] == 0.0


def test_sast_ungrounded_mitigation_does_not_suppress():
    """A hallucinated mitigation citation downgrades to needs_verify, not ruled_out."""
    by_id = {r["id"]: r for r in run_eval()["per_fixture"]}
    r = by_id["h_sast_ungrounded_mitigation_downgraded"]
    assert r["signal"] == "needs_verify"
    assert r["suppressed"] is False  # recall guard: never hide on an unverified claim


def test_sast_ruled_out_with_grounded_mitigation_suppresses():
    by_id = {r["id"]: r for r in run_eval()["per_fixture"]}
    assert by_id["g_sast_ruled_out_grounded"]["suppressed"] is True


def test_iac_empty_mitigation_does_not_suppress():
    """A mitigation asserted with an empty snippet downgrades, never hides."""
    by_id = {r["id"]: r for r in run_eval()["per_fixture"]}
    r = by_id["l_iac_empty_mitigation_downgraded"]
    assert r["signal"] == "needs_verify"
    assert r["suppressed"] is False


def test_iac_ruled_out_with_mitigation_snippet_suppresses():
    by_id = {r["id"]: r for r in run_eval()["per_fixture"]}
    assert by_id["k_iac_ruled_out_grounded"]["suppressed"] is True


def test_sast_hunter_no_chain_yields_possible_not_suppressed():
    """An uncertain hunter (no chain) keeps the finding visible as 'possible'."""
    by_id = {r["id"]: r for r in run_eval()["per_fixture"]}
    r = by_id["i_sast_hunter_no_chain_possible"]
    assert r["signal"] == "possible"
    assert r["suppressed"] is False


def test_every_fixture_matches_expected_across_all_verifiers():
    for value in run_eval()["per_fixture"]:
        assert value["matches_expected"], value


def test_run_fixture_raises_on_unknown_verifier(tmp_path):
    from runner.verification.evals.harness import Fixture, run_fixture

    fx = Fixture(
        id="x", verifier="unknown", finding={}, repo_files={},
        llm_responses=[], expected={}, label={},
    )
    with pytest.raises(ValueError, match="unsupported verifier"):
        run_fixture(fx)

