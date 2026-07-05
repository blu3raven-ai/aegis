"""Sources the premium feed pulls advisory records from.

A ``PremiumFeedSource`` knows how to fetch premium advisory records, optionally
incrementally (a ``since`` cursor) so the flywheel can refresh cheaply. The
shipped sources are placeholders: ``EmptyFeedSource`` (the honest default — no
data) and ``JsonFileFeedSource`` (load a static file, for local dev and tests).

To take Argus premium live, add a source backed by the real premium pipeline —
the vendor threat-intel ingest plus the enrichment that derives the premium
intel delta (exploit maturity, affected functions, reputation, EPSS provenance,
the alias graph) — and return it from ``argus.feed.refresh.default_feed_source``.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Protocol, runtime_checkable

from argus.matching.models import PremiumAdvisoryRecord


@runtime_checkable
class PremiumFeedSource(Protocol):
    """A source of premium advisory records for the match store."""

    def fetch(self, since: str | None = None) -> list[PremiumAdvisoryRecord]:
        """Return premium advisory records, optionally only those changed since ``since``."""
        ...


class EmptyFeedSource:
    """The honest default: a source that yields no records."""

    def fetch(self, since: str | None = None) -> list[PremiumAdvisoryRecord]:
        return []


class JsonFileFeedSource:
    """Load records from a JSON array file (local dev and tests)."""

    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)

    def fetch(self, since: str | None = None) -> list[PremiumAdvisoryRecord]:
        raw = json.loads(self._path.read_text(encoding="utf-8"))
        return [PremiumAdvisoryRecord.model_validate(entry) for entry in raw]
