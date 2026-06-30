"""Declared-range admission check for SBOM exposure analysis.

A direct dependency's manifest pins a *constraint* (e.g. npm ``^1.7.7``), not a
single version. Even when an installed component sits at a benign version, a
clean reinstall could resolve the constraint to a flagged (vulnerable) version
if that version falls inside the declared range. This module answers that single
question: does a declared range admit a given version?

Contract is strictly **fail-closed**: any uncertainty — unknown ecosystem,
unparseable range, malformed version, or an ecosystem univers cannot parse
natively (cargo and golang raise ``NotImplementedError`` on ``from_native``) —
yields ``False``. We never claim a latent exposure on a parse failure, and this
function never raises.
"""

from __future__ import annotations

from univers.version_range import RANGE_CLASS_BY_SCHEMES


def declared_range_admits(
    ecosystem: str | None,
    declared_range: str | None,
    version: str | None,
) -> bool:
    """Return True iff ``declared_range`` admits ``version`` for ``ecosystem``.

    ``ecosystem`` is the lower-cased purl type stored on ``SbomComponent``
    ("npm", "pypi", "gem", "maven", "nuget", "composer", "hex", …), which maps
    1:1 onto univers scheme names for the supported set. Cargo and golang are
    not yet supported by univers' native-range parsing, so they always read as
    not-admitted (not-latent). Any missing input, unknown scheme, or parse error
    returns False — see the module docstring for the fail-closed rationale.
    """
    if not ecosystem or not declared_range or not version:
        return False
    try:
        range_class = RANGE_CLASS_BY_SCHEMES[ecosystem.lower()]
        rng = range_class.from_native(declared_range)
        return rng.version_class(version) in rng
    except Exception:
        return False
