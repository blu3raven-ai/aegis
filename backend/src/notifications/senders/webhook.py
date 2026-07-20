"""Outbound webhook sender with per-channel HMAC-SHA256 request signing.

Signing is provided by the webhook_signing module (Phase 44).  Three headers
are added when at least one signing secret exists for the channel:

  X-Aegis-Timestamp: <unix seconds>
  X-Aegis-Signature: v1=<hex>[,v1=<hex2>]   (comma-separated during rotation)
  X-Aegis-Signature-Version: 1

Legacy config["secret"] (plain shared-secret field) is honoured for
backward compatibility; it produces the old `X-Aegis-Signature: sha256=<hex>`
header so existing receivers continue to work without changes.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
from typing import Any

from src.connectors.base import BaseSender, SendResult, TestResult
from src.connectors.http import default_client
from src.connectors.registry import register_connector
from src.notifications.destination import read_config_secret
from src.notifications.url_guard import UnsafeURLError, resolve_pinned_url_sync

logger = logging.getLogger(__name__)

_LEGACY_SIG_HEADER = "X-Aegis-Signature"


def _sign(body: bytes, secret: str) -> str:
    """Legacy sha256= signature for channels that predate Phase 44."""
    mac = hmac.new(secret.encode(), body, hashlib.sha256)
    return f"sha256={mac.hexdigest()}"


# Alias preserved for backwards compatibility
_sign_legacy = _sign


@register_connector
class GenericWebhookSender(BaseSender):
    id = "generic-webhook"
    name = "Generic Webhook"
    category = "notification"
    description = "POST findings to any HTTPS endpoint with HMAC signing"
    version = "v1.0"
    status = "stable"
    icon_slug = "webhook"
    href = "/notifications"

    def send(self, payload: dict[str, Any], config: dict[str, Any]) -> SendResult:
        url = config.get("url", "")
        if not url:
            return SendResult(success=False, error="webhook config missing url")

        try:
            url, pin_transport = resolve_pinned_url_sync(url)
        except UnsafeURLError:
            return SendResult(success=False, error="blocked: destination URL is not permitted")

        try:
            body = json.dumps(payload, default=str).encode()
            headers: dict[str, str] = {"Content-Type": "application/json"}

            signing_entries: list[dict[str, Any]] = config.get("_signing_secrets") or []
            active_raws = [
                read_config_secret(e["raw"])
                for e in signing_entries
                if isinstance(e, dict) and e.get("raw") and e.get("status") != "revoked"
            ]

            if active_raws:
                # Phase 44: versioned HMAC signature headers
                from src.notifications.webhook_signing import build_signing_headers
                signing_hdrs = build_signing_headers(payload, active_raws)
                headers.update(signing_hdrs)
            else:
                # Legacy: honour config["secret"] if present (pre-Phase 44 channels)
                legacy_secret = read_config_secret(config.get("secret", ""))
                if legacy_secret:
                    headers[_LEGACY_SIG_HEADER] = _sign(body, legacy_secret)
                    logger.warning(
                        "channel uses legacy signing secret; consider rotating to Phase 44 "
                        "HMAC headers via POST /api/v1/notifications/destinations/<id>/signing-secret"
                    )

            with default_client(transport=pin_transport) as client:
                resp = client.post(url, content=body, headers=headers)
            if 200 <= resp.status_code < 300:
                return SendResult(success=True, response_code=resp.status_code)
            # Record only the status code — never the response body, which an
            # attacker-controlled internal endpoint could use as an exfil oracle.
            return SendResult(
                success=False,
                response_code=resp.status_code,
                error=f"webhook returned status {resp.status_code}",
            )
        except Exception as exc:
            logger.warning("GenericWebhookSender.send error: %s", exc)
            return SendResult(success=False, error=str(exc)[:500])

    def test(self) -> TestResult:
        """The destination URL lives in per-destination config, which this
        no-config capability check never receives, so there is nothing to probe
        at this layer. Report available but self-report the absence of a
        liveness probe so an ops surface doesn't read this as "verified
        reachable" — delivery is exercised per-destination at send time."""
        return TestResult(
            ok=True,
            message="No liveness probe — webhook delivery is verified per-destination at send time",
        )
