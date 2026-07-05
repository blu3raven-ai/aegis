"""Sync DB-first secret resolution for webhook ingester ``verify_signature``.

The request path (FastAPI route handlers) calls :func:`match_webhook_secret`
directly with an open ``AsyncSession`` — that path stays the canonical
hot path. This module exists for callers that don't have a session in
hand and need a plain ``bool`` answer: the ingester's
:meth:`BaseIngester.verify_signature` (sync ``bool`` by base contract),
unit tests, standalone tooling, and any caller threading through
``run_db``.

The lookup order is identical to :func:`match_webhook_secret` so the
operator surface is consistent: stored ``webhook_endpoints`` rows take
precedence, then the legacy env-var fallback. On DB failure we degrade
to the env-var rather than failing closed — losing the inbound webhook
because the DB is briefly unreachable would be worse than honouring
the operator's bootstrap env-var.
"""
from __future__ import annotations

import logging
from typing import Callable

from src.settings.webhooks.service import match_webhook_secret
from src.db.helpers import run_db

logger = logging.getLogger(__name__)


def verify_with_stored_secret(
    *,
    provider: str,
    verify: Callable[[str], bool],
) -> bool:
    """Return True iff some DB-stored or env-var secret for ``provider`` satisfies ``verify``.

    ``verify`` is the provider-specific HMAC/token check curried with the
    request body and header value. The function never raises; a DB error
    degrades to the env-var fallback path inside :func:`match_webhook_secret`.
    Secrets are not surfaced through the return value or any log line.
    """
    try:
        matched = run_db(
            lambda session: match_webhook_secret(
                session, provider=provider, verify=verify
            )
        )
    except Exception:
        logger.warning(
            "webhook_secret_resolver: lookup failed for provider=%s",
            provider,
            exc_info=True,
        )
        return False
    return matched is not None
