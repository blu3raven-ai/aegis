"""Confirm argus.webhook uses the kernel signature primitive after the migration.

The local `verify_signature` function used to live in argus/webhook.py:82-94 and
duplicated HMAC-SHA256 verification. It should be deleted in favour of importing
`verify_hmac_sha256` from the kernel.
"""
from __future__ import annotations

from src.argus import webhook as argus_webhook


def test_argus_webhook_no_longer_defines_inline_verify_signature():
    """The inline verify_signature reimplementation must be removed."""
    assert not hasattr(argus_webhook, "verify_signature"), (
        "argus.webhook still defines its own verify_signature; it should "
        "import verify_hmac_sha256 from connectors.webhooks.signature instead."
    )


def test_argus_webhook_imports_kernel_primitive():
    """argus.webhook must use the kernel's verify_hmac_sha256."""
    from src.connectors.webhooks.signature import verify_hmac_sha256
    assert argus_webhook.verify_hmac_sha256 is verify_hmac_sha256
