"""The premium advisory store — the seam the live intel feed plugs into.

``PremiumAdvisoryStore`` is the read interface the matcher depends on: given a
package coordinate, return the premium advisories that may affect it. The
shipped ``InMemoryPremiumStore`` is an honest placeholder — empty unless seeded,
so ``/v1/match`` reports no premium hits until a real feed is wired.

To take Argus premium live, implement ``load_premium_store`` to return a store
backed by the premium intel feed (a database, or a periodically-synced index
keyed by ``(ecosystem, package)`` — the freshness flywheel). The matcher and the
HTTP surface above it need no changes.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Protocol, runtime_checkable

from argus.matching.models import PremiumAdvisoryRecord


@runtime_checkable
class PremiumAdvisoryStore(Protocol):
    """Lookup the matcher queries; one method, keyed by package coordinate."""

    def advisories_for(
        self, ecosystem: str, package: str
    ) -> list[PremiumAdvisoryRecord]:
        """Return premium advisories that may affect ``ecosystem``/``package``."""
        ...


class InMemoryPremiumStore:
    """Placeholder store backed by an in-memory index.

    Empty by default. Seed it from records (or from the sample file) in tests
    and local development; production replaces it with a feed-backed store.
    """

    def __init__(self, records: list[PremiumAdvisoryRecord] | None = None) -> None:
        self._by_key: dict[tuple[str, str], list[PremiumAdvisoryRecord]] = {}
        for record in records or []:
            self._by_key.setdefault(self._key(record.ecosystem, record.package), []).append(
                record
            )

    @staticmethod
    def _key(ecosystem: str, package: str) -> tuple[str, str]:
        return ecosystem.strip().lower(), package.strip().lower()

    def advisories_for(
        self, ecosystem: str, package: str
    ) -> list[PremiumAdvisoryRecord]:
        return list(self._by_key.get(self._key(ecosystem, package), []))

    def upsert(self, records: list[PremiumAdvisoryRecord]) -> None:
        """Merge ``records`` in, replacing any existing advisory with the same id.

        Lets an incremental feed refresh add or update advisories without a full
        rebuild — a record replaces the prior one for its
        ``(ecosystem, package, advisory.id)``, else it is appended.
        """
        for record in records:
            bucket = self._by_key.setdefault(
                self._key(record.ecosystem, record.package), []
            )
            for i, existing in enumerate(bucket):
                if existing.advisory.id == record.advisory.id:
                    bucket[i] = record
                    break
            else:
                bucket.append(record)

    def count(self) -> int:
        """Total advisory records held."""
        return sum(len(bucket) for bucket in self._by_key.values())

    @classmethod
    def from_json_file(cls, path: str | Path) -> "InMemoryPremiumStore":
        """Build a store from a JSON array of records (see sample_advisories.json)."""
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls([PremiumAdvisoryRecord.model_validate(entry) for entry in raw])


def load_premium_store() -> PremiumAdvisoryStore:
    """Return the premium advisory store the matcher should query.

    The store is populated from the premium feed (``argus.feed``), so the match
    pipeline is wired end-to-end. The default feed source yields nothing, so the
    store is empty and the free OSV match is unaffected until a real source is
    wired in ``argus.feed.default_feed_source``.
    """
    # Imported lazily so the matching package carries no import-time dependency
    # on the feed layer (the feed depends on matching's record model, not the
    # reverse).
    from argus.feed import fetch_premium_records

    return InMemoryPremiumStore(fetch_premium_records())
