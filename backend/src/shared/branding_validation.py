"""Pure logo data URL validation shared between the REST router and any other consumer.

Callers are responsible for raising their native error type on a non-None return.
"""
from __future__ import annotations

# 200 KiB cap on the full data URL string (base64 overhead ~33% on top of raw bytes).
_MAX_LOGO_DATA_URL_LEN = 200 * 1024
# SVG excluded: arbitrary SVG can embed JavaScript and execute in non-<img> contexts.
_ALLOWED_LOGO_MIME = frozenset({"image/png", "image/jpeg", "image/webp"})


def validate_logo_data_url(data_url: str) -> str | None:
    """Validate a logo data URL.

    Returns ``None`` on success, or a human-readable error string on failure.
    The caller decides what exception type to raise.
    """
    if len(data_url) > _MAX_LOGO_DATA_URL_LEN:
        return "Logo too large."
    if not data_url.startswith("data:"):
        return "Logo must be a data URL."
    header, _, _ = data_url.partition(",")
    if ";base64" not in header:
        return "Logo must be base64-encoded."
    mime = header.removeprefix("data:").split(";", 1)[0].strip().lower()
    if mime not in _ALLOWED_LOGO_MIME:
        return "Unsupported image type."
    return None
