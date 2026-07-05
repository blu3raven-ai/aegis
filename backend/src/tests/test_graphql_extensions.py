"""Unit tests for GraphQL safety extensions."""
from __future__ import annotations

import asyncio
import importlib
import logging
import os

import pytest
import strawberry
from graphql import GraphQLError


def _reload_extensions():
    import src.graphql.extensions as ext

    return importlib.reload(ext)


@pytest.mark.asyncio
async def test_query_timeout_extension_cancels_slow_resolver(monkeypatch):
    monkeypatch.setenv("GRAPHQL_QUERY_TIMEOUT_SECONDS", "0.05")
    ext = _reload_extensions()

    @strawberry.type
    class Q:
        @strawberry.field
        async def slow(self) -> int:
            await asyncio.sleep(5)
            return 1

    schema = strawberry.Schema(query=Q, extensions=[ext.QueryTimeoutExtension])
    result = await schema.execute("query Slow { slow }", operation_name="Slow")
    assert result.errors
    codes = [e.extensions.get("code") for e in result.errors]
    assert "TIMEOUT" in codes


@pytest.mark.asyncio
async def test_error_masking_passes_through_coded_errors():
    ext = _reload_extensions()

    @strawberry.type
    class Q:
        @strawberry.field
        async def forbidden(self) -> int:
            raise GraphQLError(
                "Forbidden",
                extensions={"code": "PERMISSION_DENIED"},
            )

    schema = strawberry.Schema(
        query=Q, extensions=[ext.ErrorMaskingExtension]
    )
    result = await schema.execute(
        "query F { forbidden }", operation_name="F"
    )
    assert result.errors
    assert result.errors[0].message == "Forbidden"
    assert result.errors[0].extensions.get("code") == "PERMISSION_DENIED"


@pytest.mark.asyncio
async def test_error_masking_swallows_uncoded_errors(caplog):
    ext = _reload_extensions()

    @strawberry.type
    class Q:
        @strawberry.field
        async def boom(self) -> int:
            raise RuntimeError("DB exploded")

    schema = strawberry.Schema(
        query=Q, extensions=[ext.ErrorMaskingExtension]
    )
    with caplog.at_level(logging.ERROR, logger="src.graphql.extensions"):
        result = await schema.execute("query B { boom }", operation_name="B")
    assert result.errors
    assert result.errors[0].message == "Internal server error"
    assert result.errors[0].extensions.get("code") == "INTERNAL_ERROR"
    assert any("DB exploded" in rec.getMessage() for rec in caplog.records)


@pytest.mark.asyncio
async def test_operation_name_required_rejects_anonymous(monkeypatch):
    monkeypatch.delenv("ENABLE_BACKEND_DOCS", raising=False)
    ext = _reload_extensions()

    @strawberry.type
    class Q:
        @strawberry.field
        def hello(self) -> str:
            return "world"

    schema = strawberry.Schema(
        query=Q, extensions=[ext.OperationNameRequiredExtension]
    )
    result = await schema.execute("{ hello }")
    assert result.errors
    assert result.errors[0].extensions.get("code") == "ANONYMOUS_OPERATION"


@pytest.mark.asyncio
async def test_operation_name_required_allows_named(monkeypatch):
    monkeypatch.delenv("ENABLE_BACKEND_DOCS", raising=False)
    ext = _reload_extensions()

    @strawberry.type
    class Q:
        @strawberry.field
        def hello(self) -> str:
            return "world"

    schema = strawberry.Schema(
        query=Q, extensions=[ext.OperationNameRequiredExtension]
    )
    result = await schema.execute(
        "query Hi { hello }", operation_name="Hi"
    )
    assert result.errors is None
    assert result.data == {"hello": "world"}


@pytest.mark.asyncio
async def test_operation_name_skipped_in_dev(monkeypatch):
    monkeypatch.setenv("ENABLE_BACKEND_DOCS", "true")
    ext = _reload_extensions()

    @strawberry.type
    class Q:
        @strawberry.field
        def hello(self) -> str:
            return "world"

    schema = strawberry.Schema(
        query=Q, extensions=[ext.OperationNameRequiredExtension]
    )
    result = await schema.execute("{ hello }")
    assert result.errors is None
    assert result.data == {"hello": "world"}


@pytest.mark.asyncio
async def test_introspection_blocker_blocks_outside_dev(monkeypatch):
    monkeypatch.delenv("ENABLE_BACKEND_DOCS", raising=False)
    ext = _reload_extensions()

    @strawberry.type
    class Q:
        @strawberry.field
        def hello(self) -> str:
            return "world"

    schema = strawberry.Schema(
        query=Q, extensions=[ext.IntrospectionBlocker]
    )
    result = await schema.execute(
        "query I { __schema { types { name } } }", operation_name="I"
    )
    assert result.errors
    assert "Introspection is disabled" in result.errors[0].message


_DEEP_QUERY = "query D { a { b { c { d { e { f { g { h { i } } } } } } } } }"


@pytest.mark.asyncio
async def test_depth_limit_rejects_deep_query_outside_dev(monkeypatch):
    monkeypatch.delenv("ENABLE_BACKEND_DOCS", raising=False)
    ext = _reload_extensions()

    @strawberry.type
    class Q:
        @strawberry.field
        def hello(self) -> str:
            return "world"

    schema = strawberry.Schema(query=Q, extensions=[ext.DepthLimitExtension])
    result = await schema.execute(_DEEP_QUERY, operation_name="D")
    assert result.errors
    assert result.errors[0].extensions.get("code") == "DEPTH_LIMIT_EXCEEDED"


@pytest.mark.asyncio
async def test_depth_limit_skipped_in_dev_so_introspection_works(monkeypatch):
    """GraphiQL's ~10-deep introspection query must succeed when docs env is set."""
    monkeypatch.setenv("ENABLE_BACKEND_DOCS", "true")
    ext = _reload_extensions()

    @strawberry.type
    class Q:
        @strawberry.field
        def hello(self) -> str:
            return "world"

    schema = strawberry.Schema(query=Q, extensions=[ext.DepthLimitExtension])
    result = await schema.execute(_DEEP_QUERY, operation_name="D")
    # Parses + runs without depth rejection; field-resolution errors are fine
    # (the test query references non-existent fields), but no DEPTH_LIMIT_EXCEEDED.
    codes = [e.extensions.get("code") for e in (result.errors or [])]
    assert "DEPTH_LIMIT_EXCEEDED" not in codes


@pytest.mark.asyncio
async def test_alias_limit_skipped_in_dev(monkeypatch):
    monkeypatch.setenv("ENABLE_BACKEND_DOCS", "true")
    ext = _reload_extensions()

    @strawberry.type
    class Q:
        @strawberry.field
        def hello(self) -> str:
            return "world"

    schema = strawberry.Schema(query=Q, extensions=[ext.AliasLimitExtension])
    aliased = "query A { " + " ".join(
        f"a{i}: hello" for i in range(15)
    ) + " }"
    result = await schema.execute(aliased, operation_name="A")
    codes = [e.extensions.get("code") for e in (result.errors or [])]
    assert "ALIAS_LIMIT_EXCEEDED" not in codes




_NESTED_ALIASES = "query A { outer { " + " ".join(f"a{i}: inner" for i in range(15)) + " } }"


@pytest.mark.asyncio
async def test_alias_limit_rejects_nested_aliases(monkeypatch):
    """Regression (GQL-01): aliases nested under a namespace field are counted.

    Real resolvers live at depth >= 2, so a top-level-only count saw 0 aliases
    for every real attack query and the cap never fired. The extension runs on
    the parsed AST before field resolution, so a flat schema + a query naming
    non-existent nested fields exercises the walk without a nested schema.
    """
    monkeypatch.delenv("ENABLE_BACKEND_DOCS", raising=False)
    ext = _reload_extensions()

    @strawberry.type
    class Q:
        @strawberry.field
        def hello(self) -> str:
            return "world"

    schema = strawberry.Schema(query=Q, extensions=[ext.AliasLimitExtension])
    result = await schema.execute(_NESTED_ALIASES, operation_name="A")
    codes = [e.extensions.get("code") for e in (result.errors or [])]
    assert "ALIAS_LIMIT_EXCEEDED" in codes


@pytest.mark.asyncio
async def test_complexity_limit_rejects_excessive_fields(monkeypatch):
    monkeypatch.delenv("ENABLE_BACKEND_DOCS", raising=False)
    ext = _reload_extensions()
    monkeypatch.setattr(ext.AliasLimitExtension, "MAX_TOTAL_FIELDS", 1)

    @strawberry.type
    class Q:
        @strawberry.field
        def hello(self) -> str:
            return "world"

    schema = strawberry.Schema(query=Q, extensions=[ext.AliasLimitExtension])
    result = await schema.execute("query C { outer { inner } }", operation_name="C")
    codes = [e.extensions.get("code") for e in (result.errors or [])]
    assert "COMPLEXITY_LIMIT_EXCEEDED" in codes


@pytest.mark.asyncio
async def test_alias_limit_allows_legit_nested_query(monkeypatch):
    monkeypatch.delenv("ENABLE_BACKEND_DOCS", raising=False)
    ext = _reload_extensions()

    @strawberry.type
    class Q:
        @strawberry.field
        def hello(self) -> str:
            return "world"

    schema = strawberry.Schema(query=Q, extensions=[ext.AliasLimitExtension])
    result = await schema.execute(
        "query L { outer { a1: inner a2: inner } }", operation_name="L"
    )
    codes = [e.extensions.get("code") for e in (result.errors or [])]
    assert "ALIAS_LIMIT_EXCEEDED" not in codes
    assert "COMPLEXITY_LIMIT_EXCEEDED" not in codes


@pytest.fixture(autouse=True, scope="module")
def _cleanup_env():
    """Restore module-level env var state after tests run."""
    yield
    for k in (
        "GRAPHQL_QUERY_TIMEOUT_SECONDS",
        "GRAPHQL_MUTATION_TIMEOUT_SECONDS",
        "ENABLE_BACKEND_DOCS",
    ):
        os.environ.pop(k, None)
    _reload_extensions()
