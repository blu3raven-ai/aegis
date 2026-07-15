"""classify_licenses turns CycloneDX licenses[] into a normalized display
string + a risk category, with OR=least-restrictive / AND=most-restrictive."""
from __future__ import annotations

from src.sbom.licenses import (
    MAX_LICENSE_LEN,
    classify_licenses,
)


def _id(spdx: str) -> dict:
    return {"license": {"id": spdx}}


def _name(name: str) -> dict:
    return {"license": {"name": name}}


def _expr(expr: str) -> dict:
    return {"expression": expr}


def test_single_spdx_ids():
    assert classify_licenses([_id("MIT")]) == _c("MIT", "permissive")
    assert classify_licenses([_id("Apache-2.0")]).category == "permissive"
    assert classify_licenses([_id("MPL-2.0")]).category == "weak-copyleft"
    assert classify_licenses([_id("LGPL-3.0-only")]).category == "weak-copyleft"
    assert classify_licenses([_id("GPL-3.0-only")]).category == "copyleft"
    assert classify_licenses([_id("AGPL-3.0-only")]).category == "network-copyleft"
    assert classify_licenses([_id("0BSD")]).category == "public-domain"


def _c(expr, cat):
    from src.sbom.licenses import LicenseClassification
    return LicenseClassification(expr, cat)


def test_deprecated_aliases_normalize_display_not_category():
    r = classify_licenses([_id("GPL-3.0")])
    assert r.expression == "GPL-3.0-only" and r.category == "copyleft"
    assert classify_licenses([_id("AGPL-3.0")]).expression == "AGPL-3.0-only"
    assert classify_licenses([_id("GPL-2.0+")]).expression == "GPL-2.0-or-later"
    assert classify_licenses([_id("LGPL-2.1")]).category == "weak-copyleft"


def test_case_and_whitespace_insensitive():
    assert classify_licenses([_id("  mit  ")]).expression == "MIT"
    assert classify_licenses([_id("apache-2.0")]).expression == "Apache-2.0"


def test_name_aliases():
    assert classify_licenses([_name("The MIT License")]) == _c("MIT", "permissive")
    assert classify_licenses([_name("Apache License, Version 2.0")]).expression == "Apache-2.0"
    assert classify_licenses([_name("GPLv3")]).category == "copyleft"


def test_or_takes_least_restrictive():
    # Dual-licensed: the integrator picks the cheapest obligation.
    assert classify_licenses([_expr("MIT OR GPL-3.0-only")]).category == "permissive"
    assert classify_licenses([_expr("GPL-2.0-only OR Apache-2.0")]).category == "permissive"


def test_and_takes_most_restrictive():
    assert classify_licenses([_expr("GPL-2.0-only AND MIT")]).category == "copyleft"
    # Operands are sorted in the canonical display.
    assert classify_licenses([_expr("GPL-2.0-only AND MIT")]).expression == "GPL-2.0-only AND MIT"


def test_malformed_operatorless_list_takes_most_restrictive():
    # Some tools emit a space-separated list with no SPDX operator. The parser
    # used to classify by the first token only and silently drop the rest, under-
    # reporting risk. Now every license token is classified, most-restrictive wins.
    assert classify_licenses([_expr("MIT GPL-3.0-only")]).category == "copyleft"
    assert classify_licenses([_expr("Apache-2.0 AGPL-3.0-only BSD-3-Clause")]).category == "network-copyleft"
    # A well-formed expression is fully consumed, so the fallback never fires.
    assert classify_licenses([_expr("MIT OR GPL-3.0-only")]).category == "permissive"


def test_multiple_independent_entries_stack():
    # No linking expression -> conjunctive -> most restrictive wins.
    assert classify_licenses([_id("MIT"), _id("GPL-3.0-only")]).category == "copyleft"
    # A permissive next to an unknown -> unknown (conservative review flag).
    assert classify_licenses([_id("MIT"), _name("Weird-Custom-Thing")]).category == "unknown"


def test_with_classifies_by_base():
    r = classify_licenses([_expr("GPL-2.0-only WITH Classpath-exception-2.0")])
    assert r.category == "copyleft"
    assert "WITH Classpath-exception-2.0" in (r.expression or "")


def test_nested_expression():
    # (MIT OR Apache-2.0) AND GPL-3.0-only -> AND of [permissive, copyleft] -> copyleft
    assert classify_licenses([_expr("(MIT OR Apache-2.0) AND GPL-3.0-only")]).category == "copyleft"


def test_proprietary_and_licenseref():
    assert classify_licenses([_id("LicenseRef-Proprietary")]).category == "proprietary"
    assert classify_licenses([_name("All Rights Reserved")]).category == "proprietary"
    assert classify_licenses([_id("LicenseRef-Acme-Internal")]).category == "unknown"
    # The structured (hyphenated) spelling — the only form a LicenseRef id can use.
    assert classify_licenses([_id("LicenseRef-All-Rights-Reserved")]).category == "proprietary"
    assert classify_licenses([_name("all-rights-reserved")]).category == "proprietary"
    assert classify_licenses([_name("All_Rights_Reserved")]).category == "proprietary"


def test_none_vs_unknown():
    # Absent license -> none (legally all-rights-reserved, surfaced not safe).
    assert classify_licenses([]) == _c(None, "none")
    # Declared NONE token -> none.
    assert classify_licenses([_id("NONE")]).category == "none"
    # Had entries but nothing classifiable -> unknown, distinct from none.
    assert classify_licenses([{}, _id("NOASSERTION")]).category == "unknown"
    assert classify_licenses([_id("NOASSERTION")]).category == "unknown"


def test_prefer_id_over_name():
    assert classify_licenses([{"license": {"id": "MIT", "name": "whatever"}}]).expression == "MIT"


def test_long_expression_category_stable_across_truncation():
    # A long OR chain ending in a copyleft AND operand: category must be computed
    # from the full token set, not the truncated display.
    big = " OR ".join(["MIT"] * 80) + " AND GPL-3.0-only"
    # Wrap so AND binds the whole OR group: (… OR …) AND GPL
    r = classify_licenses([_expr(f"({' OR '.join(['MIT'] * 80)}) AND GPL-3.0-only")])
    assert r.category == "copyleft"
    assert r.expression is not None and len(r.expression) <= MAX_LICENSE_LEN
    _ = big
