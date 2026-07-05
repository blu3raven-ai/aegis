"""Classification of OSV advisories as malicious-package reports.

The OSV mirror includes advisories whose ids are prefixed ``MAL-``: these are
malicious-package reports, not CVSS-scored vulnerabilities. The whole package
is compromised, so the correct response is removal rather than an upgrade, and
they carry no fix version and often no affected-version range at all. Callers
use this to branch on that distinct handling in one place.
"""
from __future__ import annotations

MALICIOUS_ADVISORY_PREFIX = "MAL-"


def is_malicious_advisory(advisory_id: str | None) -> bool:
    """True when the advisory id denotes a malicious-package report (``MAL-…``)."""
    return bool(advisory_id) and advisory_id.strip().upper().startswith(
        MALICIOUS_ADVISORY_PREFIX
    )
