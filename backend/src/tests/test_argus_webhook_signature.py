"""Confirm the Argus webhook receiver uses the kernel signature primitive.

The receiver used to define its own `verify_signature` inline that duplicated
HMAC-SHA256 verification. It should import `verify_hmac_sha256` from the
kernel instead. The receiver lives at
src/connectors/webhooks/providers/argus.py since it was moved into the
shared providers namespace alongside the SCM ingesters.
"""
from __future__ import annotations

from src.connectors.webhooks.providers import argus as argus_webhook


def test_argus_webhook_no_longer_defines_inline_verify_signature():
    """The inline verify_signature reimplementation must be removed."""
    assert not hasattr(argus_webhook, "verify_signature"), (
        "argus webhook still defines its own verify_signature; it should "
        "import verify_hmac_sha256 from connectors.webhooks.signature instead."
    )


def test_argus_webhook_imports_kernel_primitive():
    """The Argus webhook receiver must use the kernel's verify_hmac_sha256."""
    from src.connectors.webhooks.signature import verify_hmac_sha256
    assert argus_webhook.verify_hmac_sha256 is verify_hmac_sha256
