"""Boolean search-query grammar for the SBOM component explorer.

Splits cleanly into two halves:

* a **DB-free** recursive-descent parser (`parse_search_query`) that turns a raw
  search string into a small AST of `And`/`Or`/`Not`/`Term` nodes, raising
  `SearchQueryError` for anything malformed; and
* a SQLAlchemy **compiler** (`compile_query`) that lowers an AST into a single
  `ColumnElement` predicate over `SbomComponent`/`Asset`.

Keeping the parser free of SQLAlchemy means the grammar can be unit-tested
without a database and reused if the storage layer ever changes. Every user
value reaches SQL only as a bound `.ilike()` pattern or a parameterized equality
— never f-stringed into raw SQL — and every LIKE pattern is escaped before the
user's `*` is translated to `%`, so literal `%`/`_` in user input stay inert.

Grammar (precedence low → high):

    or_expr  := and_expr (OR and_expr)*
    and_expr := not_expr ((AND)? not_expr)*      # adjacency means AND
    not_expr := (NOT | '-') not_expr | primary
    primary  := '(' or_expr ')' | term
    term     := FIELD ':' value | bareword | quoted

`AND`/`OR`/`NOT` are operators only as bare, unquoted, case-insensitive words; a
quoted `"or"` or a `field:value` is always a literal.
"""
from __future__ import annotations

from dataclasses import dataclass, field as dc_field

from sqlalchemy import and_, func, not_, or_, select
from sqlalchemy.sql.elements import ColumnElement


class SearchQueryError(ValueError):
    """Raised for any malformed search query (bad syntax, unknown field, etc.).

    The parser surfaces every user-input problem as this type so the resolver can
    map it to a single ``BAD_INPUT`` GraphQL error rather than leaking an internal
    exception.
    """


def _escape_like(s: str) -> str:
    """Escape LIKE metacharacters so user input is treated as literal text.

    Shared with ``src.sbom.resolvers`` (which imports it from here) so the
    escaping rule lives in exactly one place.
    """
    return s.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


# ── AST ──────────────────────────────────────────────────────────────────────


@dataclass
class Term:
    """A single search atom. ``field`` is a canonical column name (or ``None`` for
    a free-text atom), ``op`` is one of ``contains``/``exact``/``wildcard``."""
    field: str | None
    op: str
    value: str


@dataclass
class And:
    children: list = dc_field(default_factory=list)


@dataclass
class Or:
    children: list = dc_field(default_factory=list)


@dataclass
class Not:
    child: object


Node = object  # And | Or | Not | Term


# ── Field catalog ────────────────────────────────────────────────────────────

# Maps an accepted field name (lower-cased) to its canonical column key.
_FIELD_ALIASES = {
    "name": "name",
    "version": "version",
    "ecosystem": "ecosystem",
    "eco": "ecosystem",
    "license": "license",
    "repo": "repo",
    "source": "source",
    "purl": "purl",
    "pkg": "purl",
    "origin": "origin",
}

_SOURCE_VALUES = {"dependencies", "containers", "container"}
_ORIGIN_VALUES = {"direct", "transitive", "unknown"}

# A leading comparator or an embedded range marker indicates a semver query,
# which PR1 does not implement — callers should use the dedicated version filter.
_VERSION_COMPARATOR_PREFIXES = ("<", ">", "=", "^", "~")


# ── Lexer ────────────────────────────────────────────────────────────────────


@dataclass
class _Tok:
    kind: str  # LPAREN | RPAREN | AND | OR | NOT | TERM
    term: object = None  # populated for kind == TERM


def _lex(s: str) -> list[_Tok]:
    """Tokenize ``s`` into structural tokens, respecting quotes and parens.

    A leading ``-`` at a token boundary is a NOT operator; a ``-`` inside a word
    (e.g. ``log4j-core``) is an ordinary character. Double-quoted spans may
    contain spaces and are never treated as operators.
    """
    toks: list[_Tok] = []
    i, n = 0, len(s)
    while i < n:
        c = s[i]
        if c.isspace():
            i += 1
            continue
        if c == "(":
            toks.append(_Tok("LPAREN"))
            i += 1
            continue
        if c == ")":
            toks.append(_Tok("RPAREN"))
            i += 1
            continue
        if c == "-":
            # Leading hyphen at a token boundary → NOT operator.
            toks.append(_Tok("NOT"))
            i += 1
            continue

        # Accumulate one word token, splicing in any quoted spans.
        buf: list[str] = []
        quoted = False
        while i < n:
            c = s[i]
            if c.isspace() or c in "()":
                break
            if c == '"':
                i += 1
                while i < n and s[i] != '"':
                    buf.append(s[i])
                    i += 1
                if i < n and s[i] == '"':
                    i += 1  # consume closing quote
                quoted = True
                continue
            buf.append(c)
            i += 1
        raw = "".join(buf)
        toks.append(_classify_word(raw, quoted))
    return toks


def _classify_word(raw: str, quoted: bool) -> _Tok:
    """Turn a raw word into a keyword token (AND/OR/NOT) or a TERM token."""
    if not quoted and ":" not in raw:
        low = raw.lower()
        if low == "and":
            return _Tok("AND")
        if low == "or":
            return _Tok("OR")
        if low == "not":
            return _Tok("NOT")
    return _Tok("TERM", term=_make_term(raw, quoted))


def _make_term(raw: str, quoted: bool) -> Term:
    """Parse a word into a `Term`, resolving the field alias and op, and rejecting
    unknown fields, empty values, and out-of-scope version comparators."""
    field_name: str | None = None
    value = raw
    if ":" in raw:
        prefix, _, rest = raw.partition(":")
        canonical = _FIELD_ALIASES.get(prefix.lower())
        if canonical is None:
            raise SearchQueryError(f"unknown field: {prefix}")
        # A pasted PURL (`pkg:npm/lodash@4.17.21`) loses its `pkg:` scheme to the
        # field split — reattach it so the value matches the stored purl column.
        if prefix.lower() == "pkg":
            value = f"pkg:{rest}"
        else:
            value = rest
        field_name = canonical
        if rest == "":
            raise SearchQueryError(f"empty field value: {prefix}")

    if value == "":
        raise SearchQueryError("empty search term")

    if quoted:
        op = "exact"
    elif "*" in value:
        op = "wildcard"
    else:
        op = "contains"

    if field_name == "version":
        if value.startswith(_VERSION_COMPARATOR_PREFIXES) or ".." in value:
            raise SearchQueryError(
                "version range/comparator search is not supported yet — "
                "use the version filter"
            )
    elif field_name == "source":
        if value.lower() not in _SOURCE_VALUES:
            raise SearchQueryError(f"invalid source value: {value}")
    elif field_name == "origin":
        if value.lower() not in _ORIGIN_VALUES:
            raise SearchQueryError(f"invalid origin value: {value}")

    return Term(field=field_name, op=op, value=value)


# ── Parser ───────────────────────────────────────────────────────────────────

_OPERAND_START = {"TERM", "NOT", "LPAREN"}


class _Parser:
    def __init__(self, toks: list[_Tok]):
        self._toks = toks
        self._i = 0

    def _peek(self) -> _Tok | None:
        return self._toks[self._i] if self._i < len(self._toks) else None

    def _advance(self) -> _Tok:
        tok = self._toks[self._i]
        self._i += 1
        return tok

    def parse(self) -> Node:
        node = self._or()
        leftover = self._peek()
        if leftover is not None:
            if leftover.kind == "RPAREN":
                raise SearchQueryError("unbalanced parentheses")
            raise SearchQueryError("unexpected token in query")
        return node

    def _or(self) -> Node:
        children = [self._and()]
        while self._peek() is not None and self._peek().kind == "OR":
            self._advance()
            children.append(self._and())
        return Or(children) if len(children) > 1 else children[0]

    def _and(self) -> Node:
        children = [self._not()]
        while True:
            tok = self._peek()
            if tok is None:
                break
            if tok.kind == "AND":
                self._advance()  # explicit AND
                children.append(self._not())
            elif tok.kind in _OPERAND_START:
                children.append(self._not())  # adjacency → implicit AND
            else:  # OR or RPAREN terminates this and-group
                break
        return And(children) if len(children) > 1 else children[0]

    def _not(self) -> Node:
        tok = self._peek()
        if tok is not None and tok.kind == "NOT":
            self._advance()
            return Not(self._not())
        return self._primary()

    def _primary(self) -> Node:
        tok = self._peek()
        if tok is None:
            raise SearchQueryError("unexpected end of query")
        if tok.kind == "LPAREN":
            self._advance()
            node = self._or()
            closing = self._peek()
            if closing is None or closing.kind != "RPAREN":
                raise SearchQueryError("unbalanced parentheses")
            self._advance()
            return node
        if tok.kind == "TERM":
            self._advance()
            return tok.term
        # An AND/OR/NOT where an operand was expected → dangling operator.
        raise SearchQueryError("dangling operator")


def parse_search_query(text: str) -> Node:
    """Parse a raw search string into an AST, raising `SearchQueryError` on any
    malformed input. The returned node is safe to hand to `compile_query`."""
    toks = _lex(text)
    if not toks:
        raise SearchQueryError("empty search query")
    return _Parser(toks).parse()


# ── Compiler ─────────────────────────────────────────────────────────────────


def _pattern(value: str, op: str) -> str:
    """Build an escaped LIKE pattern. Escaping runs first so literal ``%``/``_`` in
    user input stay inert; only the user's ``*`` becomes a ``%`` wildcard."""
    esc = _escape_like(value)
    if op == "wildcard":
        return esc.replace("*", "%")
    return f"%{esc}%"


def _col_pred(col, op: str, value: str) -> ColumnElement:
    """Predicate for one column under the given op: exact equality (case-folded)
    or an escaped ILIKE for contains/wildcard."""
    if op == "exact":
        return func.lower(col) == value.lower()
    return col.ilike(_pattern(value, op))


def compile_query(node: Node, *, SbomComponent, Asset) -> ColumnElement:
    """Lower a parsed AST into a SQLAlchemy predicate over the component/asset join.

    Models are injected to keep this module free of `src.db.models` import
    coupling. Every leaf becomes a parameterized comparison or a bound ILIKE
    pattern — user input never reaches raw SQL text.
    """
    if isinstance(node, And):
        return and_(*(compile_query(c, SbomComponent=SbomComponent, Asset=Asset) for c in node.children))
    if isinstance(node, Or):
        return or_(*(compile_query(c, SbomComponent=SbomComponent, Asset=Asset) for c in node.children))
    if isinstance(node, Not):
        return not_(compile_query(node.child, SbomComponent=SbomComponent, Asset=Asset))
    if isinstance(node, Term):
        return _compile_term(node, SbomComponent, Asset)
    raise SearchQueryError("unsupported query node")


def _compile_term(term: Term, SbomComponent, Asset) -> ColumnElement:
    f, op, value = term.field, term.op, term.value

    if f is None:
        # Preserve the legacy free-text behavior: match name OR purl OR version.
        cols = (SbomComponent.name, SbomComponent.purl, SbomComponent.version)
        return or_(*(_col_pred(c, op, value) for c in cols))

    if f == "name":
        return _col_pred(SbomComponent.name, op, value)
    if f == "version":
        return _col_pred(SbomComponent.version, op, value)
    if f == "purl":
        return _col_pred(SbomComponent.purl, op, value)
    if f == "ecosystem":
        # Ecosystems are a closed set — always an exact, case-folded match.
        return func.lower(SbomComponent.ecosystem) == value.lower()
    if f == "license":
        return or_(
            SbomComponent.license_expression.ilike(_pattern(value, "contains")),
            func.lower(SbomComponent.license_category) == value.lower(),
        )
    if f == "repo":
        # Substring match on display_name so `repo:acme` matches `acme-org/*`.
        return SbomComponent.asset_id.in_(
            select(Asset.id).where(Asset.display_name.ilike(_pattern(value, "contains")))
        )
    if f == "source":
        return Asset.type == ("repo" if value.lower() == "dependencies" else "image")
    if f == "origin":
        v = value.lower()
        if v == "direct":
            return SbomComponent.is_direct.is_(True)
        if v == "transitive":
            return SbomComponent.is_direct.is_(False)
        return SbomComponent.is_direct.is_(None)

    raise SearchQueryError(f"unknown field: {f}")
