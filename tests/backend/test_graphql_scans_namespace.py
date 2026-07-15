"""Unit tests for the `scans` GraphQL namespace.

Confirms:
- Root `scans` field returns a `ScansQuery` instance.
- Each sub-field returns the matching `*ScanningQuery` namespace type.
- Old per-scanner root fields no longer exist (guards against re-introduction).
- End-to-end `scans.<scanner>.counts` plumbing per scanner.
"""
from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest

from src.graphql.schema import (
    CodeScanningQuery,
    ContainerScanningQuery,
    DependenciesScanningQuery,
    IacScanningQuery,
    Query,
    ScansQuery,
    SecretScanningQuery,
)


def _info():
    return SimpleNamespace(context={"request": SimpleNamespace()})


@pytest.fixture
def scoped_ctx():
    with patch(
        "src.graphql.auth.get_graphql_context",
        new=AsyncMock(return_value={
            "user_id": "u", "role": "viewer", "asset_ids": ["a1", "a2"],
            "tier": "community", "request": object(), "_cache": {},
        }),
    ):
        yield


def test_scans_root_field_resolves():
    result = Query().scans()
    assert isinstance(result, ScansQuery)


def test_scans_subfields_return_namespace_types():
    scans = ScansQuery()
    assert isinstance(scans.dependencies_scanning(), DependenciesScanningQuery)
    assert isinstance(scans.code_scanning(), CodeScanningQuery)
    assert isinstance(scans.container_scanning(), ContainerScanningQuery)
    assert isinstance(scans.secret_scanning(), SecretScanningQuery)
    assert isinstance(scans.iac_scanning(), IacScanningQuery)


def test_old_root_fields_removed():
    field_names = {f.name for f in Query.__strawberry_definition__.fields}
    for stale in (
        "dependencies_scanning",
        "code_scanning",
        "container_scanning",
        "secrets_scanning",
        "iac_scanning",
    ):
        assert stale not in field_names, f"stale root field '{stale}' still registered on Query"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("scanner_attr", "query_cls", "resolver_module", "expected_tool"),
    [
        ("dependencies_scanning", DependenciesScanningQuery, "src.scans.resolvers", "dependencies_scanning"),
        ("code_scanning", CodeScanningQuery, "src.scans.resolvers", "code_scanning"),
        ("container_scanning", ContainerScanningQuery, "src.scans.resolvers", "container_scanning"),
        ("secret_scanning", SecretScanningQuery, "src.scans.resolvers", "secret_scanning"),
        ("iac_scanning", IacScanningQuery, "src.scans.resolvers", "iac_scanning"),
    ],
)
async def test_scans_counts_end_to_end(scoped_ctx, scanner_attr, query_cls, resolver_module, expected_tool):
    fake_counts = {"total": 7, "critical": 1, "high": 2, "medium": 3, "low": 1}
    sub_query = getattr(ScansQuery(), scanner_attr)()
    assert isinstance(sub_query, query_cls)

    with patch(
        f"{resolver_module}.get_severity_counts_by_asset_ids",
        return_value=fake_counts,
    ) as helper:
        result = await sub_query.counts(_info())

    helper.assert_called_once_with(["a1", "a2"], tool=expected_tool, state="open")
    assert result.total == 7
    assert result.critical == 1
    assert result.high == 2
    assert result.medium == 3
    assert result.low == 1
