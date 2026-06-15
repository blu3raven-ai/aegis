"""Per-scanner token budget pools."""
from __future__ import annotations

import os


DEFAULT_SAST_BUDGET = 200_000
DEFAULT_SCA_BUDGET = 100_000
DEFAULT_SECRETS_BUDGET = 150_000
DEFAULT_DAILY_REMAINING = 1_000_000


class ScanBudget:
    def __init__(self, *, scan_budget: int, daily_remaining: int) -> None:
        self._scan_budget = scan_budget
        self._daily_remaining = daily_remaining
        self.total_tokens_in = 0
        self.total_tokens_out = 0
        self.skip_reason: str | None = None

    def allow(self) -> bool:
        if self._daily_remaining <= 0:
            self.skip_reason = "org_daily_cap"
            return False
        used = self.total_tokens_in + self.total_tokens_out
        if used >= self._scan_budget:
            self.skip_reason = "scan_budget"
            return False
        return True

    def record(self, *, tokens_in: int, tokens_out: int) -> None:
        self.total_tokens_in += tokens_in
        self.total_tokens_out += tokens_out


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def make_sast_budget() -> ScanBudget:
    return ScanBudget(
        scan_budget=_env_int("LLM_TOKEN_BUDGET_PER_SCAN", DEFAULT_SAST_BUDGET),
        daily_remaining=_env_int("LLM_DAILY_REMAINING", DEFAULT_DAILY_REMAINING),
    )


def make_sca_budget() -> ScanBudget:
    return ScanBudget(
        scan_budget=_env_int("LLM_TOKEN_BUDGET_PER_SCAN_SCA", DEFAULT_SCA_BUDGET),
        daily_remaining=_env_int("LLM_DAILY_REMAINING", DEFAULT_DAILY_REMAINING),
    )


def make_secrets_budget() -> ScanBudget:
    return ScanBudget(
        scan_budget=_env_int("LLM_TOKEN_BUDGET_PER_SCAN_SECRETS", DEFAULT_SECRETS_BUDGET),
        daily_remaining=_env_int("LLM_DAILY_REMAINING", DEFAULT_DAILY_REMAINING),
    )
