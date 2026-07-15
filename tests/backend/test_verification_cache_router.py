"""POST /api/v1/agent/verification/cache-lookup — runner-authed, returns prior
verification results by hash so the runner can skip re-verifying."""
from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient

from src.main import app
from src.runner.registry import approve_runner, register_runner
from src.runner.storage import generate_registration_token


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def runner_token():
    raw_reg, _ = generate_registration_token()
    runner, raw_auth, err = register_runner(
        raw_token=raw_reg, name="vcache-runner", os_name="linux", arch="x86_64",
    )
    assert err is None
    approve_runner(runner["id"])
    return raw_auth


def test_cache_lookup_requires_runner_auth(client):
    resp = client.post("/api/v1/agent/verification/cache-lookup",
                       json={"tool": "code_scanning", "hashes": ["abc"]})
    assert resp.status_code == 401


def test_cache_lookup_returns_cached_results(client, runner_token):
    hit = {"abc": {"verdict": "ruled_out", "evidence": [], "exploit_chain": "",
                   "verification_metadata": {"verification_input_hash": "abc"}}}
    with patch("src.shared.finding_queries.lookup_verification_cache",
               new=AsyncMock(return_value=hit)):
        resp = client.post(
            "/api/v1/agent/verification/cache-lookup",
            headers={"Authorization": f"Bearer {runner_token}"},
            json={"tool": "code_scanning", "hashes": ["abc", "def"]},
        )
    assert resp.status_code == 200
    assert resp.json()["results"]["abc"]["verdict"] == "ruled_out"


def test_cache_lookup_rejects_oversized_batch(client, runner_token):
    resp = client.post(
        "/api/v1/agent/verification/cache-lookup",
        headers={"Authorization": f"Bearer {runner_token}"},
        json={"tool": "code_scanning", "hashes": ["h"] * 5001},
    )
    assert resp.status_code == 422
