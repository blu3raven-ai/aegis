"""Long-poll job pickup tests."""
from __future__ import annotations

import os
from unittest.mock import patch

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost:5432/test")
os.environ.setdefault("APP_SECRET", "0" * 64)

from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from src.runner.router import router as runner_router  # noqa: E402


def _make_app() -> FastAPI:
    app = FastAPI()
    app.include_router(runner_router)
    return app


_APPROVED_RUNNER = {"id": "r-1", "status": "approved"}


def test_returns_job_immediately_when_one_is_queued():
    job = {
        "id": "j-1", "jobType": "code_scanning", "org": "acme",
        "runId": "run-1", "envVars": {},
    }
    with (
        patch("src.runner.router._require_runner", return_value=(_APPROVED_RUNNER, None)),
        patch("src.runner.router.requeue_stale_jobs"),
        patch("src.runner.router.assign_next_job", return_value=job),
        patch("src.runner.router._transition_run_to_running"),
    ):
        client = TestClient(_make_app())
        resp = client.get("/api/v1/agent/jobs/next?wait=10")
    assert resp.status_code == 200
    body = resp.json()
    assert body["jobId"] == "j-1"


def test_returns_204_when_no_job_and_wait_is_zero():
    with (
        patch("src.runner.router._require_runner", return_value=(_APPROVED_RUNNER, None)),
        patch("src.runner.router.requeue_stale_jobs"),
        patch("src.runner.router.assign_next_job", return_value=None),
    ):
        client = TestClient(_make_app())
        resp = client.get("/api/v1/agent/jobs/next?wait=0")
    assert resp.status_code == 204


def test_returns_204_after_short_wait_when_no_job_queued(monkeypatch):
    """With wait=1 and never-assigning, endpoint returns 204 after ~1s (verify call count, not wall time)."""
    poll_calls = {"n": 0}

    def fake_assign(_runner_id, org=None):
        poll_calls["n"] += 1
        return None

    async def fast_sleep(_seconds):
        return None

    with (
        patch("src.runner.router._require_runner", return_value=(_APPROVED_RUNNER, None)),
        patch("src.runner.router.requeue_stale_jobs"),
        patch("src.runner.router.assign_next_job", side_effect=fake_assign),
        patch("src.runner.router.asyncio.sleep", new=fast_sleep),
    ):
        client = TestClient(_make_app())
        resp = client.get("/api/v1/agent/jobs/next?wait=1")
    assert resp.status_code == 204
    assert poll_calls["n"] >= 2


def test_picks_up_job_mid_wait(monkeypatch):
    """When assign_next_job starts returning a job mid-wait, endpoint returns 200 promptly."""
    job = {
        "id": "j-2", "jobType": "code_scanning", "org": "acme",
        "runId": "run-2", "envVars": {},
    }
    state = {"calls": 0}

    def assign_after_3(_runner_id, org=None):
        state["calls"] += 1
        return job if state["calls"] >= 3 else None

    async def fast_sleep(_seconds):
        return None

    with (
        patch("src.runner.router._require_runner", return_value=(_APPROVED_RUNNER, None)),
        patch("src.runner.router.requeue_stale_jobs"),
        patch("src.runner.router.assign_next_job", side_effect=assign_after_3),
        patch("src.runner.router._transition_run_to_running"),
        patch("src.runner.router.asyncio.sleep", new=fast_sleep),
    ):
        client = TestClient(_make_app())
        resp = client.get("/api/v1/agent/jobs/next?wait=10")
    assert resp.status_code == 200
    assert resp.json()["jobId"] == "j-2"
    assert state["calls"] >= 3


def test_wait_param_is_clamped_to_60():
    """A malicious wait=99999 must not pin a worker for hours."""
    poll_calls = {"n": 0}

    def fake_assign(_, org=None):
        poll_calls["n"] += 1
        return None

    # Simulate a synthetic clock so the deadline is hit deterministically without real waiting.
    fake_now = {"t": 1000.0}

    def fake_monotonic():
        return fake_now["t"]

    async def advancing_sleep(seconds):
        fake_now["t"] += seconds

    with (
        patch("src.runner.router._require_runner", return_value=(_APPROVED_RUNNER, None)),
        patch("src.runner.router.requeue_stale_jobs"),
        patch("src.runner.router.assign_next_job", side_effect=fake_assign),
        patch("src.runner.router.asyncio.sleep", new=advancing_sleep),
        patch("src.runner.router.time.monotonic", new=fake_monotonic),
    ):
        client = TestClient(_make_app())
        resp = client.get("/api/v1/agent/jobs/next?wait=99999")
    assert resp.status_code == 204
    # With wait clamped to 60 and 0.25s poll interval, max ~241 iterations (60/0.25 + 1).
    assert poll_calls["n"] < 500
    # And the synthetic clock should have advanced ~60s, proving the clamp worked.
    assert fake_now["t"] - 1000.0 <= 61.0


def test_returns_403_when_runner_not_approved():
    with patch(
        "src.runner.router._require_runner",
        return_value=({"id": "r-2", "status": "pending"}, None),
    ):
        client = TestClient(_make_app())
        resp = client.get("/api/v1/agent/jobs/next?wait=0")
    assert resp.status_code == 403


def test_returns_auth_error_when_require_runner_fails():
    from starlette.responses import Response as _Resp
    fake_err = _Resp(status_code=401, content=b'{"error":"no"}')
    with patch("src.runner.router._require_runner", return_value=(None, fake_err)):
        client = TestClient(_make_app())
        resp = client.get("/api/v1/agent/jobs/next?wait=0")
    assert resp.status_code == 401
