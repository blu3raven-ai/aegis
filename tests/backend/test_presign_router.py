"""Tests for POST /runner/api/jobs/{job_id}/uploads/presign."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch

from src.main import app
from src.runner.storage import generate_registration_token
from src.runner.registry import register_runner, approve_runner
from src.runner.jobs import create_job, update_job_status


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def approved_runner():
    raw_reg_token, _ = generate_registration_token()
    runner, raw_auth, err = register_runner(
        raw_token=raw_reg_token,
        name="test-presign-runner",
        os_name="linux",
        arch="x86_64",
    )
    assert err is None
    approve_runner(runner["id"])
    return {"id": runner["id"], "token": raw_auth}


@pytest.fixture
def running_job(approved_runner):
    job = create_job(
        job_type="dependencies",
        org="acme",
        run_id="run-abc",
        env_vars={},
    )
    # Directly assign and mark running so the queue state of other tests doesn't interfere
    update_job_status(job["id"], "running", runnerId=approved_runner["id"])
    return job


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def test_upload_presign_happy_path(client, approved_runner, running_job):
    with patch("src.runner.router.generate_upload_url") as mock_mint:
        mock_mint.side_effect = lambda key, expires_in, external: f"https://minio.example/{key}?sig=xyz"
        resp = client.post(
            f"/runner/api/jobs/{running_job['id']}/uploads/presign",
            headers=_auth(approved_runner["token"]),
            json={"files": ["findings.json", "sbom.cdx.json"]},
        )

    assert resp.status_code == 200
    body = resp.json()
    assert body["expiresIn"] == 300
    assert len(body["urls"]) == 2
    files = {u["file"]: u["url"] for u in body["urls"]}
    assert "findings.json" in files
    assert "sbom.cdx.json" in files
    assert "dependencies/acme/run-abc/findings.json" in files["findings.json"]


def test_upload_presign_rejects_missing_auth(client, running_job):
    resp = client.post(
        f"/runner/api/jobs/{running_job['id']}/uploads/presign",
        json={"files": ["findings.json"]},
    )
    assert resp.status_code == 401


def test_upload_presign_rejects_wrong_runner(client, approved_runner, running_job):
    raw_reg_token, _ = generate_registration_token()
    other, other_token, err = register_runner(
        raw_token=raw_reg_token,
        name="other-presign-runner",
        os_name="linux",
        arch="x86_64",
    )
    assert err is None
    approve_runner(other["id"])
    resp = client.post(
        f"/runner/api/jobs/{running_job['id']}/uploads/presign",
        headers=_auth(other_token),
        json={"files": ["findings.json"]},
    )
    assert resp.status_code == 404


def test_upload_presign_rejects_non_running_job(client, approved_runner, running_job):
    update_job_status(running_job["id"], "queued")
    resp = client.post(
        f"/runner/api/jobs/{running_job['id']}/uploads/presign",
        headers=_auth(approved_runner["token"]),
        json={"files": ["findings.json"]},
    )
    assert resp.status_code == 409


@pytest.mark.parametrize("bad_name", ["../etc/passwd", "/absolute", "name with space", ""])
def test_upload_presign_rejects_unsafe_filenames(client, approved_runner, running_job, bad_name):
    resp = client.post(
        f"/runner/api/jobs/{running_job['id']}/uploads/presign",
        headers=_auth(approved_runner["token"]),
        json={"files": ["findings.json", bad_name]},
    )
    assert resp.status_code == 400


def test_upload_presign_key_construction_uses_job_fields(client, approved_runner, running_job):
    captured_keys = []

    def _capture(key, expires_in, external):
        captured_keys.append(key)
        return f"https://minio.example/{key}"

    with patch("src.runner.router.generate_upload_url", side_effect=_capture):
        client.post(
            f"/runner/api/jobs/{running_job['id']}/uploads/presign",
            headers=_auth(approved_runner["token"]),
            json={"files": ["findings.json"]},
        )

    assert captured_keys == ["dependencies/acme/run-abc/findings.json"]


def test_sbom_list_happy_path(client, approved_runner, running_job):
    with patch("src.runner.router.list_objects") as mock_list, \
         patch("src.runner.router.generate_download_url") as mock_mint:
        mock_list.return_value = [
            "sboms/acme/service-a.cdx.json",
            "sboms/acme/service-b.cdx.json",
        ]
        mock_mint.side_effect = lambda key, expires_in: f"https://minio.example/{key}?sig=xyz"
        resp = client.get(
            f"/runner/api/jobs/{running_job['id']}/sboms",
            headers=_auth(approved_runner["token"]),
        )

    assert resp.status_code == 200
    body = resp.json()
    assert body["expiresIn"] == 300
    assert body["count"] == 2
    files = [s["file"] for s in body["sboms"]]
    assert "service-a.cdx.json" in files
    assert "service-b.cdx.json" in files


def test_sbom_list_empty_org(client, approved_runner, running_job):
    with patch("src.runner.router.list_objects", return_value=[]):
        resp = client.get(
            f"/runner/api/jobs/{running_job['id']}/sboms",
            headers=_auth(approved_runner["token"]),
        )
    assert resp.status_code == 200
    assert resp.json() == {"sboms": [], "count": 0, "expiresIn": 300}


def test_sbom_list_rejects_wrong_runner(client, approved_runner, running_job):
    # Use a second runner — it should not be able to see the first runner's job SBOMs
    raw_reg_token, _ = generate_registration_token()
    other, other_token, err = register_runner(
        raw_token=raw_reg_token,
        name="other-2",
        os_name="linux",
        arch="x86_64",
    )
    assert err is None
    approve_runner(other["id"])
    resp = client.get(
        f"/runner/api/jobs/{running_job['id']}/sboms",
        headers=_auth(other_token),
    )
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Rate limiting (200 req/runner/60s) on the presign endpoints
# ---------------------------------------------------------------------------


@pytest.fixture
def reset_rate_limit_buckets():
    """Drop the in-memory bucket so each test starts at zero counters."""
    from src.shared import rate_limit as rl
    with rl._lock:
        rl._buckets.clear()
    yield
    with rl._lock:
        rl._buckets.clear()


def _mint_upload_url(key, expires_in, external):
    return f"https://minio.example/{key}"


def test_upload_presign_allows_up_to_limit(client, approved_runner, running_job, reset_rate_limit_buckets):
    """200 calls within the 60s window must all succeed."""
    with patch("src.runner.router.generate_upload_url", side_effect=_mint_upload_url):
        for _ in range(200):
            resp = client.post(
                f"/runner/api/jobs/{running_job['id']}/uploads/presign",
                headers=_auth(approved_runner["token"]),
                json={"files": ["findings.json"]},
            )
            assert resp.status_code == 200


def test_upload_presign_rate_limits_above_threshold(client, approved_runner, running_job, reset_rate_limit_buckets):
    """The 201st call within the window must return 429."""
    with patch("src.runner.router.generate_upload_url", side_effect=_mint_upload_url):
        for _ in range(200):
            resp = client.post(
                f"/runner/api/jobs/{running_job['id']}/uploads/presign",
                headers=_auth(approved_runner["token"]),
                json={"files": ["findings.json"]},
            )
            assert resp.status_code == 200

        resp = client.post(
            f"/runner/api/jobs/{running_job['id']}/uploads/presign",
            headers=_auth(approved_runner["token"]),
            json={"files": ["findings.json"]},
        )
    assert resp.status_code == 429


def test_upload_presign_recovers_after_window_expires(client, approved_runner, running_job, reset_rate_limit_buckets, monkeypatch):
    """Calls succeed again once the sliding window expires."""
    fake_now = {"t": 1_000_000.0}

    def _now() -> float:
        return fake_now["t"]

    monkeypatch.setattr("src.shared.rate_limit.time.time", _now)

    with patch("src.runner.router.generate_upload_url", side_effect=_mint_upload_url):
        for _ in range(200):
            resp = client.post(
                f"/runner/api/jobs/{running_job['id']}/uploads/presign",
                headers=_auth(approved_runner["token"]),
                json={"files": ["findings.json"]},
            )
            assert resp.status_code == 200

        # Still in the same window — 201st must 429.
        resp = client.post(
            f"/runner/api/jobs/{running_job['id']}/uploads/presign",
            headers=_auth(approved_runner["token"]),
            json={"files": ["findings.json"]},
        )
        assert resp.status_code == 429

        # Advance past the 60s window — old entries get pruned.
        fake_now["t"] += 61.0
        resp = client.post(
            f"/runner/api/jobs/{running_job['id']}/uploads/presign",
            headers=_auth(approved_runner["token"]),
            json={"files": ["findings.json"]},
        )
        assert resp.status_code == 200


def test_upload_presign_runners_have_independent_quotas(client, approved_runner, running_job, reset_rate_limit_buckets):
    """Different runners must not share each other's quota."""
    raw_reg_token, _ = generate_registration_token()
    other, other_token, err = register_runner(
        raw_token=raw_reg_token,
        name="rate-runner-2",
        os_name="linux",
        arch="x86_64",
    )
    assert err is None
    approve_runner(other["id"])

    other_job = create_job(
        job_type="dependencies",
        org="acme",
        run_id="run-other",
        env_vars={},
    )
    update_job_status(other_job["id"], "running", runnerId=other["id"])

    with patch("src.runner.router.generate_upload_url", side_effect=_mint_upload_url):
        for _ in range(200):
            resp = client.post(
                f"/runner/api/jobs/{running_job['id']}/uploads/presign",
                headers=_auth(approved_runner["token"]),
                json={"files": ["findings.json"]},
            )
            assert resp.status_code == 200

        # First runner is over quota.
        resp = client.post(
            f"/runner/api/jobs/{running_job['id']}/uploads/presign",
            headers=_auth(approved_runner["token"]),
            json={"files": ["findings.json"]},
        )
        assert resp.status_code == 429

        # Second runner still has its own untouched quota.
        resp = client.post(
            f"/runner/api/jobs/{other_job['id']}/uploads/presign",
            headers=_auth(other_token),
            json={"files": ["findings.json"]},
        )
        assert resp.status_code == 200


def test_sbom_list_rate_limits_per_runner(client, approved_runner, running_job, reset_rate_limit_buckets):
    """SBOM list endpoint shares the runner quota with upload presign."""
    with patch("src.runner.router.list_objects", return_value=[]):
        for _ in range(200):
            resp = client.get(
                f"/runner/api/jobs/{running_job['id']}/sboms",
                headers=_auth(approved_runner["token"]),
            )
            assert resp.status_code == 200

        resp = client.get(
            f"/runner/api/jobs/{running_job['id']}/sboms",
            headers=_auth(approved_runner["token"]),
        )
    assert resp.status_code == 429
