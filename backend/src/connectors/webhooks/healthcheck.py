"""Shared :meth:`BaseIngester.test` healthcheck helper for webhook ingesters.

The request path consults ``webhook_endpoints`` rows first and falls back
to the legacy env-var; the healthcheck must report the same operator
surface so a DB-rotated secret doesn't look like "not configured" in the
admin UI.
"""
from __future__ import annotations

import logging
import os

from src.connectors.base import TestResult
from src.settings.webhooks.service import count_endpoints_for_provider
from src.db.helpers import run_db

logger = logging.getLogger(__name__)


def webhook_test_result(*, provider: str, env_var: str) -> TestResult:
    """Build a :class:`TestResult` describing how ``provider`` is configured.

    Prefers DB-backed rows over the env-var so the healthcheck mirrors the
    receiver's secret-resolution order. A DB failure degrades to the
    env-var so the healthcheck stays usable when the DB is briefly
    unreachable — same shape as :func:`match_webhook_secret`.
    """
    db_count = 0
    try:
        db_count = run_db(
            lambda session: count_endpoints_for_provider(session, provider=provider)
        )
    except Exception:
        logger.warning(
            "webhook_healthcheck: DB lookup failed for provider=%s — falling back to env-var",
            provider,
            exc_info=True,
        )

    if db_count > 0:
        return TestResult(ok=True, message=f"DB-backed ({db_count} endpoint(s) configured)")

    if os.getenv(env_var):
        return TestResult(ok=True, message=f"env-var {env_var}")

    return TestResult(ok=False, message=f"{env_var} is not configured")
