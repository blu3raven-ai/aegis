"""Regression guards: SAST AI review surface must stay deleted.

Phase B removed the AI review module. These tests ensure it doesn't sneak
back in unintentionally — if any of these guards fail, someone has
re-introduced the SAST AI review.
"""
from __future__ import annotations

import importlib

import pytest


def test_sast_ai_review_module_is_gone():
    """`src.code_scanning.ai_review` must not be importable."""
    with pytest.raises(ImportError):
        importlib.import_module("src.code_scanning.ai_review")


def test_sast_router_has_no_ai_review_endpoint():
    """The `/ai-review` route must be unreachable."""
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from src.code_scanning.router import router as code_scanning_router

    app = FastAPI()
    app.include_router(code_scanning_router)
    client = TestClient(app, raise_server_exceptions=False)

    # POST is the AI review verb per the removed endpoint.
    resp = client.post(
        "/api/v1/code-scanning/findings/some-key/ai-review",
        json={},
    )
    # 404 means the route is unregistered. Any other code (200/401/403/etc.)
    # would mean the route still exists.
    assert resp.status_code == 404, (
        f"AI review endpoint should be 404 (gone). Got {resp.status_code}."
    )


def test_valid_scan_modes_excludes_ai_review_only():
    """`ai_review_only` must not be an accepted scan mode."""
    from src.code_scanning.router import VALID_SCAN_MODES

    assert "ai_review_only" not in VALID_SCAN_MODES, (
        "Scan mode ai_review_only must be removed; current set: "
        f"{sorted(VALID_SCAN_MODES)}"
    )


def test_code_scanning_finding_dict_omits_ai_review():
    """The DB→dict shaper must not surface an ai_review field."""
    from src.storage import _finding_to_code_scanning_dict

    class _FakeFinding:
        org = "acme"
        repo = "api"
        state = "open"
        severity = "high"
        first_seen_at = None
        fixed_at = None
        engine = "semgrep"
        detail = {
            "ruleId": "test-rule",
            "ruleName": "Test",
            "filePath": "app.py",
            "startLine": 1,
            "endLine": 1,
        }
        rule_name = "Test"
        file_path = "app.py"

    result = _finding_to_code_scanning_dict(_FakeFinding(), None)
    assert "ai_review" not in result, (
        f"ai_review field must be gone from the finding dict; got keys "
        f"{sorted(result.keys())}"
    )


def test_graphql_code_scanning_finding_has_no_ai_review_field():
    """The GraphQL `CodeScanningFinding` type must have no `aiReview` field."""
    from src.graphql.code_scanning_resolvers import CodeScanningFinding

    field_names = {
        f.name for f in CodeScanningFinding.__strawberry_definition__.fields
    }
    assert "ai_review" not in field_names and "aiReview" not in field_names, (
        f"GraphQL CodeScanningFinding must not expose ai_review; "
        f"fields: {sorted(field_names)}"
    )


def test_code_scanning_config_omits_ai_review_keys():
    """SAST scanner config must not surface ai_review settings."""
    from src.shared.config import get_code_scanning_scanner_config

    config = get_code_scanning_scanner_config()
    forbidden = {
        "aiReviewEnabled",
        "aiApiKey",
        "aiBaseUrl",
        "aiModelName",
        "aiAutoClassifyOnScan",
    }
    leaked = forbidden & set(config.keys())
    assert not leaked, (
        f"Code-scanning config must not expose AI review keys; "
        f"leaked: {sorted(leaked)}"
    )
