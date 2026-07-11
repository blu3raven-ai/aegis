"""Owner extraction for a scan item — shared so every scan-scoping path parses
owners identically (dispatch, scope resolver, per-source scope refs).

An item is either an "owner/repo" slug or a full clone URL. Keeping this in one
place avoids the three copies drifting apart, which would scope scans wrong.
"""
from __future__ import annotations

from urllib.parse import urlparse


def owner_of(item: str) -> str:
    """Owner segment of an 'owner/repo' item, or the first path segment (else
    host) of a clone URL."""
    if "://" in item:
        parts = [p for p in urlparse(item).path.split("/") if p]
        return parts[0] if parts else (urlparse(item).hostname or "public")
    return item.split("/", 1)[0] if "/" in item else item
