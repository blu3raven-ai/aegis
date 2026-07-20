"""SSRF guard for tenant-configured outbound destination URLs.

Notification destinations (webhook, Slack) let a settings admin supply an
arbitrary URL. The guard logic now lives in ``src.shared.url_guard`` so the
same check can protect every admin-supplied fetch site; this module re-exports
it to keep existing senders importing from here unchanged.
"""
from src.shared.url_guard import (  # noqa: F401
    UnsafeURLError,
    assert_sendable_url,
    resolve_pinned_url_sync,
)
