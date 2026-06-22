"""Per-source schedule helpers shared by the store, API, and AutoRerunScheduler.

A source carries two independent schedules — sync (re-discover items) and scan
(auto re-run scans). Each is edited as either an interval preset or a raw cron
expression. Both resolve to a 5-field cron string so the scheduler matches them
uniformly via the existing cron matcher.
"""
from __future__ import annotations

from datetime import datetime

from src.scheduler import _matches_cron

# Interval presets offered in the dropdown, mapped to the cron they run on.
PRESET_TO_CRON: dict[str, str] = {
    "1h":  "0 * * * *",
    "3h":  "0 */3 * * *",
    "6h":  "0 */6 * * *",
    "12h": "0 */12 * * *",
    "24h": "0 0 * * *",
}

VALID_PRESETS = frozenset(PRESET_TO_CRON)
VALID_MODES = frozenset({"preset", "cron"})

# Per-field inclusive bounds for a standard 5-field cron (minute..dow).
_FIELD_BOUNDS = ((0, 59), (0, 23), (1, 31), (1, 12), (0, 6))


def _valid_cron_token(token: str, lo: int, hi: int) -> bool:
    if token == "*":
        return True
    for part in token.split(","):
        if not part:
            return False
        step_base, _, step = part.partition("/")
        if step:
            if not step.isdigit() or int(step) == 0:
                return False
        if step_base == "*":
            continue
        if "-" in step_base:
            a, _, b = step_base.partition("-")
            if not (a.isdigit() and b.isdigit()):
                return False
            if not (lo <= int(a) <= int(b) <= hi):
                return False
        else:
            if not step_base.isdigit() or not (lo <= int(step_base) <= hi):
                return False
    return True


def is_valid_cron(expression: str) -> bool:
    """Validate a 5-field cron expression (minute hour dom month dow)."""
    if not expression or not isinstance(expression, str):
        return False
    fields = expression.strip().split()
    if len(fields) != 5:
        return False
    return all(
        _valid_cron_token(field, lo, hi)
        for field, (lo, hi) in zip(fields, _FIELD_BOUNDS)
    )


def resolve_cron(mode: str, preset: str, cron: str | None) -> str | None:
    """Resolve a schedule (mode + preset + cron) to the cron string it runs on."""
    if mode == "cron":
        return cron if cron and is_valid_cron(cron) else None
    return PRESET_TO_CRON.get(preset)


def is_schedule_due(mode: str, preset: str, cron: str | None, now: datetime) -> bool:
    """True when the resolved schedule fires at *now* (minute granularity)."""
    resolved = resolve_cron(mode, preset, cron)
    return bool(resolved) and _matches_cron(resolved, now)
