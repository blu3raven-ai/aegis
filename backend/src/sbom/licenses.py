"""SBOM component license classification — the single source of truth for
turning a CycloneDX ``licenses[]`` declaration into one normalized display
string and one risk category.

Pure and data-driven: adding an SPDX id is one table entry, never a call-site
change. The category is computed once at ingest (so it is indexable and
filterable at the SQL layer) from the full untruncated token set, so truncating
the display string can never change the verdict.

Combining rule: a dual-licensed ``A OR B`` takes the *least* restrictive operand
(the integrator chooses); ``A AND B``, ``WITH``, and multiple independent
``licenses[]`` entries stack obligations, so the *most* restrictive wins. Absent
licenses are ``none`` (legally all-rights-reserved — surfaced, not treated as
safe); declared-but-unclassifiable is ``unknown``.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

CATEGORIES = (
    "public-domain", "permissive", "weak-copyleft", "copyleft",
    "network-copyleft", "proprietary", "unknown", "none",
)

# Worst-first triage rank. Two axes folded into one scale: copyleft strength for
# known licenses, with an "uncertainty band" (proprietary/unknown/none) sitting
# above weak-copyleft because each needs human review before the component is
# trusted.
CATEGORY_RANK: dict[str, int] = {
    "public-domain": 0,
    "permissive": 1,
    "weak-copyleft": 2,
    "none": 3,
    "unknown": 4,
    "proprietary": 5,
    "copyleft": 6,
    "network-copyleft": 7,
}

MAX_LICENSE_LEN = 512

# Canonical SPDX id -> category. Add a license = add a line here.
SPDX_CATEGORY: dict[str, str] = {
    # permissive
    "MIT": "permissive", "Apache-2.0": "permissive", "Apache-1.1": "permissive",
    "BSD-2-Clause": "permissive", "BSD-3-Clause": "permissive", "ISC": "permissive",
    "Zlib": "permissive", "PostgreSQL": "permissive", "Python-2.0": "permissive",
    "BSD-2-Clause-Patent": "permissive", "BlueOak-1.0.0": "permissive",
    # public domain / no-obligation
    "0BSD": "public-domain", "Unlicense": "public-domain", "CC0-1.0": "public-domain",
    "WTFPL": "public-domain",
    # weak / file-level copyleft
    "MPL-2.0": "weak-copyleft", "MPL-1.1": "weak-copyleft",
    "EPL-2.0": "weak-copyleft", "EPL-1.0": "weak-copyleft",
    "CDDL-1.0": "weak-copyleft", "CDDL-1.1": "weak-copyleft",
    "LGPL-2.0-only": "weak-copyleft", "LGPL-2.1-only": "weak-copyleft",
    "LGPL-2.1-or-later": "weak-copyleft", "LGPL-3.0-only": "weak-copyleft",
    "LGPL-3.0-or-later": "weak-copyleft",
    # strong copyleft
    "GPL-2.0-only": "copyleft", "GPL-2.0-or-later": "copyleft",
    "GPL-3.0-only": "copyleft", "GPL-3.0-or-later": "copyleft",
    # network copyleft
    "AGPL-3.0-only": "network-copyleft", "AGPL-3.0-or-later": "network-copyleft",
}

# Deprecated / legacy SPDX ids -> canonical. Category is invariant to the
# only/or-later distinction, so this only fixes the display string + lookup.
DEPRECATED_ALIASES: dict[str, str] = {
    "GPL-2.0": "GPL-2.0-only", "GPL-3.0": "GPL-3.0-only",
    "LGPL-2.0": "LGPL-2.0-only", "LGPL-2.1": "LGPL-2.1-only", "LGPL-3.0": "LGPL-3.0-only",
    "AGPL-3.0": "AGPL-3.0-only",
    "GPL-2.0+": "GPL-2.0-or-later", "GPL-3.0+": "GPL-3.0-or-later",
    "LGPL-2.1+": "LGPL-2.1-or-later", "LGPL-3.0+": "LGPL-3.0-or-later",
    "AGPL-3.0+": "AGPL-3.0-or-later",
}

# Normalized free-text name -> SPDX id. Keys are the output of _normalize_name.
NAME_ALIASES: dict[str, str] = {
    "mit": "MIT",
    "apache 2.0": "Apache-2.0", "apache 2": "Apache-2.0", "apache": "Apache-2.0",
    "apache software": "Apache-2.0",
    "bsd": "BSD-3-Clause", "new bsd": "BSD-3-Clause", "modified bsd": "BSD-3-Clause",
    "simplified bsd": "BSD-2-Clause",
    "isc": "ISC", "zlib": "Zlib",
    "mozilla public 2.0": "MPL-2.0", "mpl 2.0": "MPL-2.0",
    "eclipse public 2.0": "EPL-2.0",
    "gplv3": "GPL-3.0-only", "gpl 3": "GPL-3.0-only", "gpl 3.0": "GPL-3.0-only",
    "gplv2": "GPL-2.0-only", "gpl 2": "GPL-2.0-only", "gpl 2.0": "GPL-2.0-only",
    "lgplv3": "LGPL-3.0-only", "lgplv2.1": "LGPL-2.1-only",
    "agplv3": "AGPL-3.0-only", "agpl 3.0": "AGPL-3.0-only",
    "unlicense": "Unlicense", "wtfpl": "WTFPL", "cc0": "CC0-1.0",
}

# Separator-tolerant so the hyphenated LicenseRef form (the only spelling a
# machine-readable SPDX LicenseRef id can use) and the spaced free-text name
# both classify as proprietary.
_PROPRIETARY_PAT = re.compile(
    r"proprietary|commercial|eula|all[\s_-]+rights[\s_-]+reserved", re.IGNORECASE
)
# Strip filler words so "The Apache License, Version 2.0" -> "apache 2.0".
_NAME_FILLER = re.compile(r"\b(the|license|licence|version|v)\b", re.IGNORECASE)


@dataclass(frozen=True)
class LicenseClassification:
    """Normalized display string (None when no license was declared) and the
    computed risk category (always one of CATEGORIES)."""
    expression: str | None
    category: str


def category_rank(category: str | None) -> int:
    return CATEGORY_RANK.get(category or "", -1)


def _normalize_name(text: str) -> str:
    t = _NAME_FILLER.sub(" ", text.lower())
    t = re.sub(r"[^a-z0-9. ]", " ", t)
    return re.sub(r"\s+", " ", t).strip()


def _canonical_id(token: str) -> str:
    """Canonicalize a single SPDX id token: trim, fix deprecated aliases, and
    restore canonical casing when the id is known."""
    tok = token.strip()
    tok = DEPRECATED_ALIASES.get(tok, tok)
    # Case-insensitive match against known ids -> canonical casing.
    lower = tok.lower()
    for canonical in SPDX_CATEGORY:
        if canonical.lower() == lower:
            return canonical
    # Deprecated alias declared in a different case.
    for dep, canonical in DEPRECATED_ALIASES.items():
        if dep.lower() == lower:
            return canonical
    return tok


def _classify_token(token: str) -> tuple[str, str]:
    """Classify one operand (an SPDX id, LicenseRef, or free-text name).
    Returns (category, display)."""
    raw = token.strip()
    if not raw:
        return "unknown", raw
    upper = raw.upper()
    if upper == "NONE":
        return "none", "NONE"
    if upper == "NOASSERTION":
        return "unknown", "NOASSERTION"

    canonical = _canonical_id(raw)
    if canonical in SPDX_CATEGORY:
        return SPDX_CATEGORY[canonical], canonical

    # LicenseRef-* or a free-text name.
    if _PROPRIETARY_PAT.search(raw):
        return "proprietary", raw
    if raw.lower().startswith("licenseref"):
        return "unknown", raw

    # Free-text name resolution.
    resolved = NAME_ALIASES.get(_normalize_name(raw))
    if resolved and resolved in SPDX_CATEGORY:
        return SPDX_CATEGORY[resolved], resolved
    return "unknown", raw


# ── SPDX expression evaluation ───────────────────────────────────────────────

_EXPR_TOKEN = re.compile(r"\(|\)|[^()\s]+")


def _tokenize_expression(expr: str) -> list[str]:
    return _EXPR_TOKEN.findall(expr)


def _eval_expression(tokens: list[str]) -> tuple[str, str]:
    """Recursive-descent eval of an SPDX expression. OR -> least restrictive
    (min rank), AND/WITH -> most restrictive (max rank). Returns (category,
    canonical display)."""
    pos = [0]

    def peek() -> str | None:
        return tokens[pos[0]] if pos[0] < len(tokens) else None

    def advance() -> str:
        tok = tokens[pos[0]]
        pos[0] += 1
        return tok

    def parse_or() -> tuple[str, str]:
        cats_disps = [parse_and()]
        while (peek() or "").upper() == "OR":
            advance()
            cats_disps.append(parse_and())
        if len(cats_disps) == 1:
            return cats_disps[0]
        cat = min((c for c, _ in cats_disps), key=category_rank)
        disp = " OR ".join(sorted(d for _, d in cats_disps))
        return cat, disp

    def parse_and() -> tuple[str, str]:
        cats_disps = [parse_with()]
        while (peek() or "").upper() == "AND":
            advance()
            cats_disps.append(parse_with())
        if len(cats_disps) == 1:
            return cats_disps[0]
        cat = max((c for c, _ in cats_disps), key=category_rank)
        disp = " AND ".join(sorted(d for _, d in cats_disps))
        return cat, disp

    def parse_with() -> tuple[str, str]:
        cat, disp = parse_primary()
        while (peek() or "").upper() == "WITH":
            advance()
            _, exc = parse_primary()  # exception classifies by the base license
            disp = f"{disp} WITH {exc}"
        return cat, disp

    def parse_primary() -> tuple[str, str]:
        tok = peek()
        if tok == "(":
            advance()
            cat, disp = parse_or()
            if peek() == ")":
                advance()
            return cat, disp
        if tok is None:
            return "unknown", ""
        return _classify_token(advance())

    parsed = parse_or()
    if pos[0] >= len(tokens):
        return parsed
    # Leftover, unparsed tokens — a malformed or space/comma-separated list
    # (some tools emit "MIT GPL-3.0-only" with no operator). Don't silently
    # classify by the first license alone; classify every license token and take
    # the most restrictive (max rank), matching the multiple-entry rule, so a
    # trailing copyleft isn't lost and licence risk isn't under-reported.
    cats_disps = [
        _classify_token(t)
        for t in tokens
        if t not in ("(", ")") and t.upper() not in ("AND", "OR", "WITH")
    ]
    if not cats_disps:
        return parsed
    cat = max((c for c, _ in cats_disps), key=category_rank)
    disp = " ".join(d for _, d in cats_disps if d)
    return cat, disp


def _entry_classification(entry: dict) -> tuple[str, str] | None:
    """One ``licenses[]`` entry -> (category, display), or None to skip an
    empty/malformed entry (while the caller still records that an entry existed)."""
    expr = entry.get("expression")
    if isinstance(expr, str) and expr.strip():
        return _eval_expression(_tokenize_expression(expr))
    lic = entry.get("license")
    if isinstance(lic, dict):
        ident = lic.get("id")
        name = lic.get("name")
        if isinstance(ident, str) and ident.strip():
            return _classify_token(ident)
        if isinstance(name, str) and name.strip():
            return _classify_token(name)
    return None


def classify_licenses(licenses: list[dict]) -> LicenseClassification:
    """Classify a CycloneDX ``licenses[]`` array into a display string + category."""
    if not licenses:
        return LicenseClassification(None, "none")

    classified: list[tuple[str, str]] = []
    for entry in licenses:
        if isinstance(entry, dict):
            res = _entry_classification(entry)
            if res is not None:
                classified.append(res)

    if not classified:
        # Entries existed but none classified (all malformed / NOASSERTION-only):
        # that is "unknown" (we had data we could not classify), not "none".
        return LicenseClassification("", "unknown")

    # Multiple independent entries stack (conjunctive) -> most restrictive wins.
    category = max((c for c, _ in classified), key=category_rank)
    displays = sorted({d for _, d in classified if d})
    expression = " AND ".join(displays)[:MAX_LICENSE_LEN] if displays else None
    return LicenseClassification(expression, category)
