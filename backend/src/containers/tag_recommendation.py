"""Select newer image tags from a registry tag list, conservatively.

The runner dumps a repo's raw tag list into a sidecar; picking which tags are
"newer" happens here so the selection logic is testable and the runner stays
dumb. Deliberately conservative: a tag is only ever compared against others that
share its exact flavour (the non-numeric suffix, e.g. ``-alpine``), must parse
as a dotted numeric version, and must be strictly greater. Anything that doesn't
parse cleanly yields no suggestion rather than a wrong one — a bad "upgrade to
X" is worse than none.
"""
from __future__ import annotations

import re

# v?<numeric dotted version><flavour suffix>, e.g. "v1.2.3-alpine" -> ("1.2.3", "-alpine").
_TAG_RE = re.compile(r"^v?(\d+(?:\.\d+)*)(.*)$")


def _parse(tag: str) -> tuple[tuple[int, ...], str] | None:
    m = _TAG_RE.match(tag.strip())
    if not m:
        return None
    try:
        version = tuple(int(p) for p in m.group(1).split("."))
    except ValueError:
        return None
    if not version:
        return None
    return version, m.group(2)


def select_newer_tags(current_tag: str | None, tags: list[str], *, limit: int = 3) -> list[str]:
    """Newer tags of the same flavour as ``current_tag``, highest first (≤ limit).

    Returns [] when the current tag is unparseable, when no candidate shares its
    flavour, or when nothing is strictly newer — never a cross-flavour or
    pre-release guess (a stable ``1.2.3`` won't match ``1.3.0-rc1``: different
    flavour)."""
    if not current_tag:
        return []
    current = _parse(current_tag)
    if current is None:
        return []
    cur_version, cur_flavour = current

    newer: list[tuple[tuple[int, ...], str]] = []
    seen: set[str] = set()
    for tag in tags:
        if tag in seen:
            continue
        seen.add(tag)
        parsed = _parse(tag)
        if parsed is None:
            continue
        version, flavour = parsed
        if flavour == cur_flavour and version > cur_version:
            newer.append((version, tag))

    newer.sort(key=lambda vt: vt[0], reverse=True)
    return [tag for _, tag in newer[:limit]]
