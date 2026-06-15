"""Per-scan token budget guard."""
from __future__ import annotations

from runner.verification.budget import (
    DEFAULT_DAILY_REMAINING,
    DEFAULT_SAST_BUDGET,
    DEFAULT_SCA_BUDGET,
    DEFAULT_SECRETS_BUDGET,
    ScanBudget,
    make_sast_budget,
    make_sca_budget,
    make_secrets_budget,
)


def test_initial_budget_allows_calls():
    b = ScanBudget(scan_budget=1000, daily_remaining=10_000)
    assert b.allow() is True


def test_blocks_when_scan_budget_exceeded():
    b = ScanBudget(scan_budget=200, daily_remaining=10_000)
    b.record(tokens_in=100, tokens_out=80)
    assert b.allow() is True
    b.record(tokens_in=30, tokens_out=0)
    assert b.allow() is False
    assert b.skip_reason == "scan_budget"


def test_blocks_first_call_when_daily_exhausted():
    b = ScanBudget(scan_budget=1000, daily_remaining=0)
    assert b.allow() is False
    assert b.skip_reason == "org_daily_cap"


def test_aggregates_tokens():
    b = ScanBudget(scan_budget=1000, daily_remaining=10_000)
    b.record(tokens_in=100, tokens_out=50)
    b.record(tokens_in=200, tokens_out=80)
    assert b.total_tokens_in == 300
    assert b.total_tokens_out == 130


def test_make_sca_budget_default(monkeypatch):
    monkeypatch.delenv("LLM_TOKEN_BUDGET_PER_SCAN_SCA", raising=False)
    monkeypatch.delenv("LLM_DAILY_REMAINING", raising=False)
    b = make_sca_budget()
    assert b._scan_budget == DEFAULT_SCA_BUDGET
    assert b._daily_remaining == DEFAULT_DAILY_REMAINING


def test_make_sca_budget_env_override(monkeypatch):
    monkeypatch.setenv("LLM_TOKEN_BUDGET_PER_SCAN_SCA", "50000")
    monkeypatch.setenv("LLM_DAILY_REMAINING", "5000000")
    b = make_sca_budget()
    assert b._scan_budget == 50_000
    assert b._daily_remaining == 5_000_000


def test_make_sca_budget_invalid_env_falls_back(monkeypatch):
    monkeypatch.setenv("LLM_TOKEN_BUDGET_PER_SCAN_SCA", "not-a-number")
    monkeypatch.delenv("LLM_DAILY_REMAINING", raising=False)
    b = make_sca_budget()
    assert b._scan_budget == DEFAULT_SCA_BUDGET


def test_make_sast_budget_default(monkeypatch):
    monkeypatch.delenv("LLM_TOKEN_BUDGET_PER_SCAN", raising=False)
    monkeypatch.delenv("LLM_DAILY_REMAINING", raising=False)
    assert make_sast_budget()._scan_budget == DEFAULT_SAST_BUDGET


def test_make_secrets_budget_default(monkeypatch):
    monkeypatch.delenv("LLM_TOKEN_BUDGET_PER_SCAN_SECRETS", raising=False)
    monkeypatch.delenv("LLM_DAILY_REMAINING", raising=False)
    assert make_secrets_budget()._scan_budget == DEFAULT_SECRETS_BUDGET


def test_per_scanner_budgets_independent(monkeypatch):
    monkeypatch.setenv("LLM_TOKEN_BUDGET_PER_SCAN", "100")
    monkeypatch.setenv("LLM_TOKEN_BUDGET_PER_SCAN_SCA", "200")
    monkeypatch.setenv("LLM_TOKEN_BUDGET_PER_SCAN_SECRETS", "300")
    monkeypatch.delenv("LLM_DAILY_REMAINING", raising=False)
    assert make_sast_budget()._scan_budget == 100
    assert make_sca_budget()._scan_budget == 200
    assert make_secrets_budget()._scan_budget == 300


def test_sca_default_smaller_than_sast(monkeypatch):
    monkeypatch.delenv("LLM_TOKEN_BUDGET_PER_SCAN", raising=False)
    monkeypatch.delenv("LLM_TOKEN_BUDGET_PER_SCAN_SCA", raising=False)
    assert make_sca_budget()._scan_budget < make_sast_budget()._scan_budget
