"""Internal record shape for the premium advisory store.

A ``PremiumAdvisoryRecord`` is one entry in the premium feed: a package
coordinate, the vulnerable version ranges, the public advisory payload, and the
premium intel delta. The live feed produces these; the matcher turns a matched
record into a wire ``MatchItem``.
"""
from __future__ import annotations

from pydantic import BaseModel, Field

from argus.models import MatchAdvisory, PremiumIntel


class VulnerableRange(BaseModel):
    """One affected interval, in OSV's half-open semantics.

    A version is affected when ``version >= introduced`` and, when set,
    ``version < fixed`` and ``version <= last_affected``. ``introduced = "0"``
    with no upper bound means every version is affected.
    """

    introduced: str = "0"
    fixed: str | None = None
    last_affected: str | None = None


class PremiumAdvisoryRecord(BaseModel):
    """A premium advisory keyed to a single package coordinate."""

    ecosystem: str
    package: str
    advisory: MatchAdvisory
    ranges: list[VulnerableRange] = Field(default_factory=list)
    intel: PremiumIntel = Field(default_factory=PremiumIntel)
