"""Unit tests for the DB-free SBOM search grammar (parser + SQL compiler).

These never touch a database: the parser is pure, and the compiler is exercised
by compiling against the Postgres dialect and inspecting the bound parameters,
so escaping and column structure can be asserted deterministically.
"""
from __future__ import annotations

import os

import pytest

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost:5432/test")
os.environ.setdefault("APP_SECRET", "0" * 64)

from sqlalchemy.dialects import postgresql  # noqa: E402

from src.db.models import Asset, SbomComponent  # noqa: E402
from src.sbom.search_query import (  # noqa: E402
    And,
    Not,
    Or,
    SearchQueryError,
    Term,
    compile_query,
    parse_search_query,
)


def _compiled(node):
    """Return (sql_text, params) for a compiled AST against the PG dialect."""
    expr = compile_query(node, SbomComponent=SbomComponent, Asset=Asset)
    c = expr.compile(dialect=postgresql.dialect())
    return str(c), dict(c.params)


def _param_values(node) -> list:
    return list(_compiled(node)[1].values())


# ── Tokenization ─────────────────────────────────────────────────────────────


def test_quoted_value_with_spaces_is_one_term():
    node = parse_search_query('name:"foo bar"')
    assert node == Term(field="name", op="exact", value="foo bar")


def test_quoted_bareword_is_exact():
    assert parse_search_query('"lodash"') == Term(field=None, op="exact", value="lodash")


def test_hyphen_inside_word_is_one_bareword():
    assert parse_search_query("log4j-core") == Term(field=None, op="contains", value="log4j-core")


def test_leading_hyphen_is_not():
    assert parse_search_query("-flask") == Not(Term(field=None, op="contains", value="flask"))


def test_quoted_hyphen_value_is_literal_not_operator():
    assert parse_search_query('"-flask"') == Term(field=None, op="exact", value="-flask")


def test_parens_are_their_own_tokens():
    node = parse_search_query("(a)")
    assert node == Term(field=None, op="contains", value="a")


# ── Precedence & grouping ────────────────────────────────────────────────────


def test_or_lower_than_and():
    # `a OR b c` == `a OR (b AND c)`
    node = parse_search_query("a OR b c")
    assert node == Or([
        Term(None, "contains", "a"),
        And([Term(None, "contains", "b"), Term(None, "contains", "c")]),
    ])


def test_parens_override_precedence():
    node = parse_search_query("(a OR b) c")
    assert node == And([
        Or([Term(None, "contains", "a"), Term(None, "contains", "b")]),
        Term(None, "contains", "c"),
    ])


def test_nested_parens():
    node = parse_search_query("((a OR b) AND (c OR d))")
    assert node == And([
        Or([Term(None, "contains", "a"), Term(None, "contains", "b")]),
        Or([Term(None, "contains", "c"), Term(None, "contains", "d")]),
    ])


def test_implicit_and_equals_explicit_and():
    assert parse_search_query("a b") == parse_search_query("a AND b")


def test_keywords_are_case_insensitive():
    lhs = parse_search_query("a or b and not c")
    rhs = parse_search_query("a OR b AND NOT c")
    assert lhs == rhs
    assert lhs == Or([
        Term(None, "contains", "a"),
        And([Term(None, "contains", "b"), Not(Term(None, "contains", "c"))]),
    ])


def test_not_binds_tighter_than_and():
    node = parse_search_query("NOT a b")
    assert node == And([Not(Term(None, "contains", "a")), Term(None, "contains", "b")])


# ── Fields & aliases ─────────────────────────────────────────────────────────


@pytest.mark.parametrize("field,canonical", [
    ("name", "name"),
    ("version", "version"),
    ("ecosystem", "ecosystem"),
    ("eco", "ecosystem"),
    ("license", "license"),
    ("repo", "repo"),
    ("source", "source"),
    ("purl", "purl"),
    ("origin", "origin"),
])
def test_field_aliases_resolve_to_canonical(field, canonical):
    value = {"source": "dependencies", "origin": "direct"}.get(canonical, "x")
    node = parse_search_query(f"{field}:{value}")
    assert isinstance(node, Term)
    assert node.field == canonical


def test_field_name_is_case_insensitive():
    assert parse_search_query("ECO:npm") == Term(field="ecosystem", op="contains", value="npm")


def test_pkg_alias_reconstructs_purl_value():
    node = parse_search_query("pkg:npm/lodash@4.17.21")
    assert node == Term(field="purl", op="contains", value="pkg:npm/lodash@4.17.21")


def test_purl_field_keeps_scheme_in_value():
    node = parse_search_query("purl:pkg:npm/lodash@4.17.21")
    assert node == Term(field="purl", op="contains", value="pkg:npm/lodash@4.17.21")


def test_name_wildcard():
    assert parse_search_query("name:lo*") == Term(field="name", op="wildcard", value="lo*")


def test_name_quoted_exact():
    assert parse_search_query('name:"lodash"') == Term(field="name", op="exact", value="lodash")


# ── Backward compatibility ───────────────────────────────────────────────────


def test_bareword_compiles_to_legacy_three_column_or():
    sql, params = _compiled(parse_search_query("lodash"))
    # name OR purl OR version, all ILIKE %lodash%.
    assert sql.count("ILIKE") == 3
    assert "name" in sql and "purl" in sql and "version" in sql
    assert all(v == "%lodash%" for v in params.values())


# ── Compiler: field semantics ────────────────────────────────────────────────


def test_ecosystem_compiles_to_exact_lower():
    sql, params = _compiled(parse_search_query("ecosystem:NPM"))
    assert "lower" in sql.lower()
    assert "npm" in params.values()


def test_source_dependencies_maps_to_repo_type():
    sql, params = _compiled(parse_search_query("source:dependencies"))
    assert "repo" in params.values()


def test_source_containers_maps_to_image_type():
    sql, params = _compiled(parse_search_query("source:containers"))
    assert "image" in params.values()


def test_origin_direct_is_boolean_true():
    sql, _ = _compiled(parse_search_query("origin:direct"))
    assert "is_direct" in sql
    assert "true" in sql.lower()


def test_repo_uses_substring_subquery():
    sql, params = _compiled(parse_search_query("repo:acme"))
    assert "SELECT" in sql.upper()  # asset_id IN (subquery)
    assert "%acme%" in params.values()


def test_license_matches_expression_or_category():
    sql, params = _compiled(parse_search_query("license:gpl"))
    assert "license_expression" in sql
    assert "license_category" in sql
    assert "%gpl%" in params.values()
    assert "gpl" in params.values()


# ── Compiler: escaping / injection safety ────────────────────────────────────


def test_like_metachars_are_escaped():
    # `name:50%_x` (no '*') → contains → %, _ escaped inside the bound pattern.
    values = _param_values(parse_search_query("name:50%_x"))
    assert values == ["%50\\%\\_x%"]


def test_wildcard_star_becomes_percent_but_literal_percent_stays_escaped():
    # `name:50%*` → wildcard; the literal % stays escaped, the '*' becomes '%'.
    values = _param_values(parse_search_query("name:50%*"))
    assert values == ["50\\%%"]


def test_backslash_is_escaped():
    values = _param_values(parse_search_query("name:a\\b"))
    assert values == ["%a\\\\b%"]


# ── Errors ───────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("query", [
    "(a OR b",       # missing close paren
    "a)",            # extra close paren
    "name:",         # empty field value
    "bogus:foo",     # unknown field
    "a OR",          # trailing operator
    "a AND",         # trailing operator
    "OR a",          # leading operator
    "version:<4.17.21",
    "version:>=2.0",
    "version:^1.0",
    "version:~1.0",
    "version:1..2",
    "source:bogus",
    "origin:sideways",
    "",              # empty query
    "   ",           # whitespace-only query
])
def test_malformed_queries_raise(query):
    with pytest.raises(SearchQueryError):
        parse_search_query(query)


def test_plain_version_is_allowed():
    assert parse_search_query("version:1.2.3") == Term(field="version", op="contains", value="1.2.3")


def test_version_wildcard_is_allowed():
    assert parse_search_query("version:1.2.*") == Term(field="version", op="wildcard", value="1.2.*")


def test_error_is_value_error_subclass():
    # Resolver maps only SearchQueryError to BAD_INPUT; keep the hierarchy stable.
    assert issubclass(SearchQueryError, ValueError)
