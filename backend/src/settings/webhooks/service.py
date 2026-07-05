"""DB-backed webhook secret store.

The :class:`src.db.models.WebhookEndpoint` row holds an encrypted secret
per ``(org_id, provider)``. The encryption context is namespaced
``webhook_endpoint:<provider>`` so a ciphertext written for one provider
cannot be decrypted as if it belonged to another.

Receivers don't know the ``org_id`` of an inbound request before the body
is authenticated — they call :func:`match_webhook_secret` with the
provider, body and header, which walks every row for that provider and
returns the :class:`WebhookSecretMatch` for the first row whose ``verify``
callable accepts the request. The match carries the ``org_id`` that owns
the accepting secret so callers can attribute the request to the tenant
that actually authenticated rather than to attacker-controlled payload
fields. A trailing env-var fallback keeps existing bootstrap deployments
working; that path is single-tenant so its match carries ``org_id=None``.

Adding a per-provider header-scoped index would let us avoid the linear
walk, but webhook endpoints are typically small (one per org per
provider) so the linear walk is fine for v0.5 — revisit if a deployment
configures dozens of orgs.
"""
from __future__ import annotations

import logging
import os
import secrets
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable, Iterable

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.db.models import WebhookEndpoint
from src.shared.encryption import decrypt, encrypt

logger = logging.getLogger(__name__)


PROVIDERS: tuple[str, ...] = ("github", "gitlab", "bitbucket", "azure_devops", "jenkins")

# Each provider's env-var fallback name, used when no DB row matches.
_ENV_VAR_BY_PROVIDER: dict[str, str] = {
    "github": "GITHUB_WEBHOOK_SECRET",
    "gitlab": "GITLAB_WEBHOOK_SECRET",
    "bitbucket": "BITBUCKET_WEBHOOK_SECRET",
    "azure_devops": "AZURE_DEVOPS_WEBHOOK_SECRET",
    "jenkins": "JENKINS_WEBHOOK_SECRET",
}


def _context(provider: str) -> str:
    return f"webhook_endpoint:{provider}"


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _generate_secret() -> str:
    return secrets.token_urlsafe(48)


def _serialize(row: WebhookEndpoint) -> dict[str, object]:
    return {
        "id": row.id,
        "provider": row.provider,
        "last4": row.last4,
        "createdAt": row.created_at.isoformat(),
        "updatedAt": row.updated_at.isoformat(),
        "rotatedAt": row.rotated_at.isoformat() if row.rotated_at else None,
    }


def _new_id() -> str:
    return secrets.token_hex(16)


async def count_endpoints_for_provider(
    session: AsyncSession, *, provider: str
) -> int:
    """Return the number of configured endpoints for ``provider`` across all orgs.

    Used by ingester ``test()`` healthchecks to report whether a DB-backed
    secret exists without exposing the plaintext or org context."""
    if provider not in PROVIDERS:
        return 0
    stmt = select(WebhookEndpoint.id).where(WebhookEndpoint.provider == provider)
    rows = (await session.execute(stmt)).all()
    return len(rows)


async def list_endpoints(session: AsyncSession, *, org_id: str) -> list[dict[str, object]]:
    stmt = (
        select(WebhookEndpoint)
        .where(WebhookEndpoint.org_id == org_id)
        .order_by(WebhookEndpoint.provider.asc())
    )
    rows = (await session.execute(stmt)).scalars().all()
    return [_serialize(row) for row in rows]


async def create_endpoint(
    session: AsyncSession, *, org_id: str, provider: str
) -> dict[str, object]:
    """Generate a new secret for ``(org_id, provider)`` or raise on conflict.

    Returns the row payload with the plaintext ``secret`` embedded — the
    caller must surface this to the operator exactly once.
    """
    if provider not in PROVIDERS:
        raise ValueError(f"unsupported provider {provider!r}")

    existing = (
        await session.execute(
            select(WebhookEndpoint).where(
                WebhookEndpoint.org_id == org_id,
                WebhookEndpoint.provider == provider,
            )
        )
    ).scalar_one_or_none()
    if existing is not None:
        raise WebhookEndpointConflict(provider)

    secret = _generate_secret()
    row = WebhookEndpoint(
        id=_new_id(),
        org_id=org_id,
        provider=provider,
        secret_enc=encrypt(secret, context=_context(provider)),
        last4=secret[-4:],
    )
    session.add(row)
    await session.flush()
    payload = _serialize(row)
    payload["secret"] = secret
    return payload


async def rotate_endpoint(
    session: AsyncSession, *, org_id: str, endpoint_id: str
) -> dict[str, object] | None:
    row = (
        await session.execute(
            select(WebhookEndpoint).where(
                WebhookEndpoint.id == endpoint_id,
                WebhookEndpoint.org_id == org_id,
            )
        )
    ).scalar_one_or_none()
    if row is None:
        return None

    secret = _generate_secret()
    row.secret_enc = encrypt(secret, context=_context(row.provider))
    row.last4 = secret[-4:]
    row.rotated_at = _utcnow()
    await session.flush()
    payload = _serialize(row)
    payload["secret"] = secret
    return payload


async def delete_endpoint(
    session: AsyncSession, *, org_id: str, endpoint_id: str
) -> bool:
    row = (
        await session.execute(
            select(WebhookEndpoint).where(
                WebhookEndpoint.id == endpoint_id,
                WebhookEndpoint.org_id == org_id,
            )
        )
    ).scalar_one_or_none()
    if row is None:
        return False
    await session.delete(row)
    return True


class WebhookEndpointConflict(Exception):
    """Raised when an endpoint for the given provider already exists."""

    def __init__(self, provider: str) -> None:
        super().__init__(f"webhook endpoint for provider {provider!r} already exists")
        self.provider = provider


@dataclass(frozen=True)
class WebhookSecretMatch:
    """A verified inbound webhook secret and the tenant that owns it.

    ``org_id`` / ``endpoint_id`` are ``None`` for the env-var fallback,
    which is a single-tenant bootstrap credential with no tenant binding.
    The plaintext ``secret`` lets callers short-circuit duplicate
    verification work; it MUST NOT be logged.
    """

    org_id: str | None
    endpoint_id: str | None
    secret: str


async def _iter_db_secrets(
    session: AsyncSession, provider: str
) -> Iterable[tuple[str, str, str]]:
    """Yield ``(org_id, endpoint_id, plaintext)`` for each decryptable row."""
    stmt = select(
        WebhookEndpoint.org_id, WebhookEndpoint.id, WebhookEndpoint.secret_enc
    ).where(WebhookEndpoint.provider == provider)
    result = await session.execute(stmt)
    rows_out: list[tuple[str, str, str]] = []
    for org_id, endpoint_id, enc in result.all():
        try:
            # strict: an undecryptable secret raises (logged below) instead of
            # returning "" — otherwise a rotated key makes a configured endpoint
            # silently read as unconfigured and inbound webhook auth fails blind.
            plaintext = decrypt(enc, context=_context(provider), strict=True)
        except Exception:
            logger.warning(
                "webhook_endpoints: decrypt failed for provider=%s endpoint=%s — "
                "skipping row (encryption key may have changed)",
                provider,
                endpoint_id,
            )
            continue
        if plaintext:
            rows_out.append((org_id, endpoint_id, plaintext))
    return rows_out


async def match_webhook_secret(
    session: AsyncSession,
    *,
    provider: str,
    verify: Callable[[str], bool],
) -> WebhookSecretMatch | None:
    """Find a stored secret for ``provider`` that satisfies ``verify``.

    ``verify`` is the provider-specific signature/auth check curried with
    the request body and header — see the call sites in
    ``src.connectors.webhooks.providers``. The first matching row wins;
    on no match we fall back to the env-var so existing bootstrap
    deployments continue to work.

    Returns a :class:`WebhookSecretMatch` carrying the owning ``org_id`` so
    the caller can attribute the request to the tenant that authenticated;
    ``None`` if nothing matched (caller MUST treat as authentication
    failure). The env-var fallback yields ``org_id=None`` (unbound).

    A DB-side error degrades to the env-var fallback rather than failing
    closed — losing the inbound webhook because the DB is unreachable
    would be worse than honouring the operator's env-var.
    """
    if provider not in PROVIDERS:
        return None

    try:
        candidates = list(await _iter_db_secrets(session, provider))
    except Exception:
        logger.warning(
            "webhook_endpoints: DB lookup failed for provider=%s — falling back to env-var",
            provider,
            exc_info=True,
        )
        candidates = []

    for org_id, endpoint_id, plaintext in candidates:
        if verify(plaintext):
            return WebhookSecretMatch(
                org_id=org_id, endpoint_id=endpoint_id, secret=plaintext
            )

    env_secret = os.getenv(_ENV_VAR_BY_PROVIDER[provider], "")
    if env_secret and verify(env_secret):
        return WebhookSecretMatch(org_id=None, endpoint_id=None, secret=env_secret)
    return None
