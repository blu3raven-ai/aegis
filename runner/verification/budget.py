"""Per-scanner token budget pools.

The backend ships LLM_* limits inside job['envVars'] (see backend
src/scans/service.py). Read them through JobEnv — the runner process env
does NOT see those values because the runner agent does not propagate
envVars to os.environ (and shouldn't: jobs run concurrently in threads,
so a shared os.environ would be a cross-job leak).
"""
from __future__ import annotations

from runner.scanners._shared import JobEnv


DEFAULT_SAST_BUDGET = 200_000
DEFAULT_SECRETS_BUDGET = 150_000
DEFAULT_IAC_BUDGET = 100_000
DEFAULT_AGENT_BUDGET = 80_000
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


def make_sast_budget(env: JobEnv) -> ScanBudget:
    return ScanBudget(
        scan_budget=env.get_int("LLM_TOKEN_BUDGET_PER_SCAN", DEFAULT_SAST_BUDGET),
        daily_remaining=env.get_int("LLM_DAILY_REMAINING", DEFAULT_DAILY_REMAINING),
    )


def make_secrets_budget(env: JobEnv) -> ScanBudget:
    return ScanBudget(
        scan_budget=env.get_int("LLM_TOKEN_BUDGET_PER_SCAN_SECRETS", DEFAULT_SECRETS_BUDGET),
        daily_remaining=env.get_int("LLM_DAILY_REMAINING", DEFAULT_DAILY_REMAINING),
    )


def make_iac_budget(env: JobEnv) -> ScanBudget:
    return ScanBudget(
        scan_budget=env.get_int("LLM_TOKEN_BUDGET_PER_SCAN_IAC", DEFAULT_IAC_BUDGET),
        daily_remaining=env.get_int("LLM_DAILY_REMAINING", DEFAULT_DAILY_REMAINING),
    )


def make_agent_budget(env: JobEnv) -> ScanBudget:
    return ScanBudget(
        scan_budget=env.get_int("LLM_TOKEN_BUDGET_PER_SCAN_AGENT", DEFAULT_AGENT_BUDGET),
        daily_remaining=env.get_int("LLM_DAILY_REMAINING", DEFAULT_DAILY_REMAINING),
    )
