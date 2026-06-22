"""GraphQL safety extensions.

Each extension is registered on the schema and runs in declaration order.
``ErrorMaskingExtension`` MUST be registered last so its post-yield body
sees errors produced by every other extension and resolver before they
reach the client.
"""
from __future__ import annotations

import asyncio
import logging
import os
import traceback
from collections.abc import Iterator

from graphql import GraphQLError
from graphql.error import GraphQLError as GqlCoreError
from graphql.execution.execute import ExecutionResult as GraphQLExecutionResult
from strawberry.extensions import SchemaExtension
from strawberry.types.execution import ExecutionResult as StrawberryExecutionResult

from src.graphql.limits import check_query_depth


logger = logging.getLogger(__name__)


def _is_dev() -> bool:
    return os.getenv("ENABLE_BACKEND_DOCS", "").lower() == "true"


def _float_env(name: str, default: float) -> float:
    raw = os.getenv(name)
    if raw is None or raw == "":
        return default
    try:
        return float(raw)
    except ValueError:
        return default


# Wall-clock budgets, evaluated once at import.
_QUERY_TIMEOUT_SECONDS = _float_env("GRAPHQL_QUERY_TIMEOUT_SECONDS", 5.0)
_MUTATION_TIMEOUT_SECONDS = _float_env("GRAPHQL_MUTATION_TIMEOUT_SECONDS", 30.0)


class DepthLimitExtension(SchemaExtension):
    """Reject queries exceeding max nesting depth.

    Skipped in dev so GraphiQL's ~10-deep introspection query can populate
    the schema explorer. Same env gate as IntrospectionBlocker — the route
    is only reachable when ENABLE_BACKEND_DOCS=true.
    """

    def on_operation(self) -> Iterator[None]:
        if not _is_dev():
            query = self.execution_context.query
            if query:
                try:
                    check_query_depth(query)
                except ValueError as e:
                    raise GraphQLError(
                        str(e),
                        extensions={"code": "DEPTH_LIMIT_EXCEEDED"},
                    ) from e
        yield


class AliasLimitExtension(SchemaExtension):
    """Reject queries with excessive field aliases.

    Skipped in dev for the same reason as DepthLimitExtension — GraphiQL
    issues aliased introspection queries that can exceed the prod cap.
    """

    MAX_ALIASES = 10

    def on_operation(self) -> Iterator[None]:
        if not _is_dev():
            doc = self.execution_context.graphql_document
            if doc:
                alias_count = self._count_aliases(doc)
                if alias_count > self.MAX_ALIASES:
                    raise GraphQLError(
                        f"Too many aliases ({alias_count}). Max {self.MAX_ALIASES}.",
                        extensions={"code": "ALIAS_LIMIT_EXCEEDED"},
                    )
        yield

    def _count_aliases(self, doc) -> int:
        count = 0
        for definition in doc.definitions:
            selections = (
                getattr(getattr(definition, "selection_set", None), "selections", None)
                or []
            )
            for selection in selections:
                if getattr(selection, "alias", None):
                    count += 1
        return count


class IntrospectionBlocker(SchemaExtension):
    """Block introspection queries outside dev."""

    def on_operation(self) -> Iterator[None]:
        if not _is_dev():
            query = self.execution_context.query or ""
            if "__schema" in query or "__type" in query:
                raise GraphQLError(
                    "Introspection is disabled",
                    extensions={"code": "INTROSPECTION_DISABLED"},
                )
        yield


class OperationNameRequiredExtension(SchemaExtension):
    """Require every operation to carry a name so logs/metrics are attributable."""

    def on_operation(self) -> Iterator[None]:
        if not _is_dev():
            name = self.execution_context.operation_name
            if not name:
                raise GraphQLError(
                    "Operation must be named for observability",
                    extensions={"code": "ANONYMOUS_OPERATION"},
                )
        yield


class QueryTimeoutExtension(SchemaExtension):
    """Wall-clock budget around resolver execution.

    Different budgets apply to queries vs mutations because mutations
    legitimately do more work (writes, fan-out to runners). Enforced per
    resolver via ``asyncio.wait_for`` so a stuck async resolver is cancelled,
    not merely flagged after the fact. The deadline is anchored at operation
    start so the budget spans the whole resolver tree.
    """

    _t0: float = 0.0
    _budget: float = 0.0

    def _operation_budget(self) -> float:
        try:
            op_type = self.execution_context.operation_type
        except Exception:
            op_type = None
        op_name = getattr(op_type, "name", None) or str(op_type or "")
        return (
            _MUTATION_TIMEOUT_SECONDS
            if "MUTATION" in op_name.upper()
            else _QUERY_TIMEOUT_SECONDS
        )

    def on_operation(self) -> Iterator[None]:
        try:
            self._t0 = asyncio.get_running_loop().time()
        except RuntimeError:
            self._t0 = 0.0
        self._budget = self._operation_budget()
        yield

    async def resolve(self, _next, root, info, *args, **kwargs):
        loop = asyncio.get_running_loop()
        t0 = self._t0 or loop.time()
        remaining = self._budget - (loop.time() - t0)
        if remaining <= 0:
            raise GraphQLError(
                "Query timeout exceeded",
                extensions={"code": "TIMEOUT"},
            )

        result = _next(root, info, *args, **kwargs)
        if not asyncio.iscoroutine(result) and not hasattr(result, "__await__"):
            return result

        try:
            return await asyncio.wait_for(_await_value(result), timeout=remaining)
        except asyncio.TimeoutError as e:
            raise GraphQLError(
                "Query timeout exceeded",
                extensions={"code": "TIMEOUT"},
            ) from e


async def _await_value(value):
    return await value


class ErrorMaskingExtension(SchemaExtension):
    """Mask errors lacking an explicit ``extensions["code"]``.

    Resolvers opt-in to user-visible failure by raising
    ``GraphQLError(..., extensions={"code": "..."})``. Anything else is
    treated as an internal leak risk — logged server-side with full traceback
    and replaced with a generic INTERNAL_ERROR before it reaches the client.
    Must run last so it sees other extensions' errors too.
    """

    def on_operation(self) -> Iterator[None]:
        yield
        result = self.execution_context.result
        if result is None:
            return

        if isinstance(result, (GraphQLExecutionResult, StrawberryExecutionResult)):
            self._mask(result)
        else:
            initial = getattr(result, "initial_result", None)
            if initial is not None:
                self._mask(initial)

    def _mask(self, result) -> None:
        errors = result.errors
        if not errors:
            return

        masked: list[GraphQLError] = []
        for err in errors:
            if self._has_code(err):
                masked.append(err)
                continue

            original = getattr(err, "original_error", None) or err
            tb = "".join(
                traceback.format_exception(type(original), original, original.__traceback__)
            )
            logger.error(
                "Masking uncoded GraphQL error: %s\n%s",
                getattr(original, "args", (str(original),)),
                tb,
            )

            masked.append(
                GraphQLError(
                    "Internal server error",
                    nodes=getattr(err, "nodes", None),
                    source=getattr(err, "source", None),
                    positions=getattr(err, "positions", None),
                    path=getattr(err, "path", None),
                    extensions={"code": "INTERNAL_ERROR"},
                )
            )

        result.errors = masked

    @staticmethod
    def _has_code(err) -> bool:
        if not isinstance(err, GqlCoreError):
            return False
        ext = err.extensions or {}
        return bool(ext.get("code"))
