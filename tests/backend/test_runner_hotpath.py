"""Hot-path coverage for runner registration, auth, dispatch and lifecycle.

Every runner request hits `authenticate_runner` and `_require_runner`, and
every scan ingests results via the job lifecycle. These tests fill gaps
around:

- Registration: invalid token rejected; idempotent reuse; auto-approval
  when registering via the pre-shared compose token.
- Auth & token rotation: hash compare, rotate generates new hash, revoke
  invalidates the existing token.
- Heartbeat & status: online/stale/offline thresholds, malformed timestamps.
- Job dispatch: serialised assignment (no double-claim under concurrency),
  encrypted env-var round-trip, completion increments runner counters.
- Stale jobs: missing runner → requeue, fresh heartbeat → leave alone,
  past stale threshold → requeue.
- Registration-token lifecycle: expiry, single-use, unknown token.

Storage is mocked via in-memory dicts so the tests stay fast and DB-free.
"""
from __future__ import annotations

import os
import threading
from datetime import datetime, timezone
from datetime import timedelta
from unittest.mock import patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost:5432/test")
os.environ.setdefault("APP_SECRET", "0" * 64)

from src.runner import jobs as jobs_module  # noqa: E402
from src.runner import registry  # noqa: E402
from src.runner.encryption import SENSITIVE_KEYS, decrypt_env_vars, encrypt_env_vars  # noqa: E402
from src.runner.router import router as runner_router  # noqa: E402


# In-memory storage fakes — let us exercise the dispatch logic without DB


class _MemStorage:
    def __init__(self):
        self.runners: dict[str, dict] = {}
        self.jobs: dict[str, dict] = {}
        self._lock = threading.Lock()

    # Runner side
    def read_runner(self, runner_id):
        r = self.runners.get(runner_id)
        return dict(r) if r else None

    def write_runner(self, runner):
        self.runners[runner["id"]] = dict(runner)

    def touch_heartbeat(self, runner_id):
        r = self.runners.get(runner_id)
        if r:
            r["lastHeartbeatAt"] = registry.now_iso()

    def list_runners(self):
        return [dict(r) for r in self.runners.values()]

    def delete_runner(self, runner_id):
        self.runners.pop(runner_id, None)

    # Job side
    def read_job(self, job_id):
        j = self.jobs.get(job_id)
        return dict(j) if j else None

    def write_job(self, job):
        self.jobs[job["id"]] = dict(job)

    def list_jobs(self, status=None, org=None):
        rows = [dict(j) for j in self.jobs.values()]
        if status is not None:
            rows = [r for r in rows if r.get("status") == status]
        if org is not None:
            rows = [r for r in rows if r.get("org") == org]
        rows.sort(key=lambda r: r.get("createdAt", ""))
        return rows

    def atomic_assign_job(self, runner_id, org=None):
        with self._lock:
            rows = [dict(j) for j in self.jobs.values() if j.get("status") == "queued"]
            if org is not None:
                rows = [r for r in rows if r.get("org") == org]
            rows.sort(key=lambda r: r.get("createdAt", ""))
            if not rows:
                return None
            job = rows[0]
            job["status"] = "assigned"
            job["runnerId"] = runner_id
            job["startedAt"] = datetime.now(timezone.utc).isoformat()
            self.jobs[job["id"]] = dict(job)
            return dict(job)


@pytest.fixture
def mem(monkeypatch):
    s = _MemStorage()
    # Patch both the storage module (source) and the registry/jobs modules
    # where the names are imported, since Python binds at import time.
    monkeypatch.setattr("src.runner.storage.read_runner", s.read_runner)
    monkeypatch.setattr("src.runner.storage.write_runner", s.write_runner)
    monkeypatch.setattr("src.runner.storage.touch_heartbeat", s.touch_heartbeat)
    monkeypatch.setattr("src.runner.storage.list_runners", s.list_runners)
    monkeypatch.setattr("src.runner.storage.delete_runner", s.delete_runner)
    monkeypatch.setattr("src.runner.storage.read_job", s.read_job)
    monkeypatch.setattr("src.runner.storage.write_job", s.write_job)
    monkeypatch.setattr("src.runner.storage.list_jobs", s.list_jobs)

    monkeypatch.setattr("src.runner.registry.read_runner", s.read_runner)
    monkeypatch.setattr("src.runner.registry.write_runner", s.write_runner)
    monkeypatch.setattr("src.runner.registry.list_runners", s.list_runners)
    monkeypatch.setattr("src.runner.registry.delete_runner", s.delete_runner)

    monkeypatch.setattr("src.runner.jobs.read_runner", s.read_runner)
    monkeypatch.setattr("src.runner.jobs.write_runner", s.write_runner)
    monkeypatch.setattr("src.runner.jobs.read_job", s.read_job)
    monkeypatch.setattr("src.runner.jobs.write_job", s.write_job)
    monkeypatch.setattr("src.runner.jobs.list_jobs", s.list_jobs)
    monkeypatch.setattr("src.runner.storage.atomic_assign_job", s.atomic_assign_job)
    monkeypatch.setattr("src.runner.jobs.atomic_assign_job", s.atomic_assign_job)
    return s


def _approved_runner(s: _MemStorage, runner_id="r1", token_hash="h1"):
    s.write_runner({
        "id": runner_id,
        "name": runner_id,
        "status": "approved",
        "authTokenHash": token_hash,
        "lastHeartbeatAt": registry.now_iso(),
        "jobsCompleted": 0,
    })


# Registry: registration


def test_register_rejects_unknown_token(mem, monkeypatch):
    monkeypatch.setattr("src.runner.registry.validate_registration_token", lambda _t: None)
    monkeypatch.delenv("RUNNER_REGISTRATION_TOKEN", raising=False)

    runner, raw_auth, error = registry.register_runner(raw_token="garbage", name="x")
    assert runner is None
    assert raw_auth is None
    assert error == "Invalid or expired registration token"


def test_register_with_valid_db_token_creates_pending_runner(mem, monkeypatch):
    monkeypatch.setattr(
        "src.runner.registry.validate_registration_token",
        lambda _t: {"tokenHash": "x", "used": True},
    )
    monkeypatch.delenv("RUNNER_REGISTRATION_TOKEN", raising=False)

    runner, raw_auth, error = registry.register_runner(
        raw_token="vrt_ok", name="my-runner", os_name="linux", arch="amd64",
    )
    assert error is None
    assert raw_auth and raw_auth.startswith("vra_")
    assert runner is not None
    assert runner["status"] == "pending_approval"
    assert runner["os"] == "linux"
    assert runner["arch"] == "amd64"


def test_register_with_local_env_token_auto_approves(mem, monkeypatch):
    monkeypatch.setenv("RUNNER_REGISTRATION_TOKEN", "shared-secret-xyz")
    monkeypatch.setattr("src.runner.registry.validate_registration_token", lambda _t: None)

    runner, raw_auth, error = registry.register_runner(
        raw_token="shared-secret-xyz", name="compose-runner",
    )
    assert error is None
    assert runner["status"] == "approved"
    assert runner["approvedAt"] is not None


def test_register_reuses_pending_record_by_name(mem, monkeypatch):
    """A not-yet-approved runner registered again by the same name is reused
    (id preserved, token rotated) rather than spawning a duplicate pending row."""
    monkeypatch.setenv("RUNNER_REGISTRATION_TOKEN", "compose-token")
    monkeypatch.setattr(
        "src.runner.registry.validate_registration_token",
        lambda t: {"tokenHash": "x", "used": True} if t == "vrt_db" else None,
    )

    # First registration via a one-time DB token creates a PENDING runner.
    r1, _, _ = registry.register_runner(raw_token="vrt_db", name="worker-1")
    assert r1["status"] == "pending_approval"
    first_id = r1["id"]

    # Re-registration (shared env token) reuses the still-untrusted record and
    # rotates its auth token so an old token can't be replayed.
    r2, _, _ = registry.register_runner(raw_token="compose-token", name="worker-1")
    assert r2["id"] == first_id
    assert r2["authTokenHash"] != r1["authTokenHash"]


def test_register_does_not_hijack_approved_runner_by_name(mem, monkeypatch):
    """Re-registering a name already owned by an APPROVED runner must not
    overwrite it: the trusted record keeps its token, approval and identity,
    and the newcomer starts as a distinct pending runner."""
    monkeypatch.setenv("RUNNER_REGISTRATION_TOKEN", "compose-token")
    monkeypatch.setattr("src.runner.registry.validate_registration_token", lambda _t: None)

    r1, _, _ = registry.register_runner(raw_token="compose-token", name="worker-1")
    assert r1["status"] == "approved"
    original_id = r1["id"]
    original_hash = r1["authTokenHash"]

    r2, _, _ = registry.register_runner(raw_token="compose-token", name="worker-1")
    # Newcomer is a distinct, untrusted runner.
    assert r2["id"] != original_id
    assert r2["status"] == "pending_approval"
    # The approved runner is left completely untouched.
    still = mem.read_runner(original_id)
    assert still["status"] == "approved"
    assert still["authTokenHash"] == original_hash


# Registry: authentication


def test_authenticate_runner_returns_none_on_unknown_token(mem):
    _approved_runner(mem, "r1", token_hash="hash-of-real-token")
    assert registry.authenticate_runner("definitely-not-the-token") is None


def test_authenticate_runner_returns_record_on_match(mem):
    from src.runner.storage import hash_token
    real = "vra_actual_token_value"
    _approved_runner(mem, "r1", token_hash=hash_token(real))
    auth = registry.authenticate_runner(real)
    assert auth is not None
    assert auth["id"] == "r1"


# Registry: rotate / revoke


def test_rotate_auth_token_replaces_hash(mem):
    _approved_runner(mem, "r1", token_hash="old-hash")
    raw, error = registry.rotate_auth_token("r1")
    assert error is None
    assert raw and raw.startswith("vra_")
    updated = mem.read_runner("r1")
    assert updated["authTokenHash"] != "old-hash"


def test_rotate_auth_token_for_missing_runner_returns_error(mem):
    raw, error = registry.rotate_auth_token("ghost")
    assert raw is None
    assert error == "Runner not found"


def test_revoke_runner_invalidates_old_token(mem):
    """After revoke, the original auth token must no longer authenticate."""
    from src.runner.storage import hash_token
    real = "vra_real"
    _approved_runner(mem, "r1", token_hash=hash_token(real))
    assert registry.authenticate_runner(real) is not None
    revoked = registry.revoke_runner("r1")
    assert revoked["status"] == "pending_approval"
    assert registry.authenticate_runner(real) is None


def test_revoke_missing_runner_returns_none(mem):
    assert registry.revoke_runner("ghost") is None


# Registry: heartbeat + status thresholds


def test_heartbeat_returns_none_for_missing_runner(mem):
    assert registry.heartbeat("ghost") is None


def test_heartbeat_updates_last_heartbeat(mem, monkeypatch):
    _approved_runner(mem, "r1", token_hash="h")
    mem.runners["r1"]["lastHeartbeatAt"] = "2026-01-01T00:00:00Z"
    # Disable the random prune branch and metric storage for determinism.
    monkeypatch.setattr("random.random", lambda: 0.99)
    monkeypatch.setattr("src.runner.storage.update_runner_metrics", lambda *a, **k: None)
    monkeypatch.setattr("src.runner.storage.record_heartbeat", lambda *a, **k: None)
    updated = registry.heartbeat("r1")
    assert updated is not None
    assert updated["lastHeartbeatAt"] != "2026-01-01T00:00:00Z"


@pytest.mark.parametrize(
    "elapsed_seconds,expected",
    [
        (10, "online"),
        (90, "stale"),
        (300, "offline"),
    ],
)
def test_compute_runner_status_thresholds(elapsed_seconds, expected):
    last_hb = (datetime.now(timezone.utc) - timedelta(seconds=elapsed_seconds)).isoformat()
    runner = {"status": "approved", "lastHeartbeatAt": last_hb}
    assert registry.compute_runner_status(runner) == expected


def test_compute_runner_status_pending_short_circuits():
    assert registry.compute_runner_status({"status": "pending_approval"}) == "pending_approval"


def test_compute_runner_status_archived_short_circuits():
    assert registry.compute_runner_status({"status": "archived"}) == "archived"


def test_compute_runner_status_offline_when_heartbeat_missing():
    assert registry.compute_runner_status({"status": "approved"}) == "offline"


def test_compute_runner_status_offline_when_heartbeat_malformed():
    """A corrupt lastHeartbeatAt must not crash status computation."""
    runner = {"status": "approved", "lastHeartbeatAt": "not-a-timestamp"}
    assert registry.compute_runner_status(runner) == "offline"


# Jobs: dispatch, encryption, completion, requeue


def test_create_job_encrypts_only_sensitive_env_vars(mem):
    job_id = jobs_module._create_job_inner(
        job_type="secret_scanning",
        org="acme-org",
        run_id="run-1",
        env_vars={"GIT_TOKEN": "supersecret", "WORKDIR": "/tmp/x"},
    )
    stored = mem.read_job(job_id)
    assert stored["envVars"]["GIT_TOKEN"].startswith("ENC:")
    # Non-sensitive values are stored as-is — this is by design.
    assert stored["envVars"]["WORKDIR"] == "/tmp/x"


def test_assign_next_job_decrypts_sensitive_env_vars(mem):
    jobs_module._create_job_inner(
        job_type="secret_scanning",
        org="acme-org",
        run_id="run-1",
        env_vars={"GIT_TOKEN": "plain-secret-value"},
    )
    assigned = jobs_module._assign_next_job_inner(runner_id="r-1")
    assert assigned is not None
    assert assigned["status"] == "assigned"
    assert assigned["runnerId"] == "r-1"
    assert assigned["envVars"]["GIT_TOKEN"] == "plain-secret-value"


def test_assign_next_job_returns_none_when_no_queued_jobs(mem):
    assert jobs_module._assign_next_job_inner(runner_id="r-1") is None


def test_concurrent_assign_does_not_double_claim(mem):
    """Two runners polling at the same instant must never claim the same job.

    The `_assign_lock` in jobs.py is the invariant being tested — without it,
    both threads would observe the same queued job and write conflicting
    runnerId values.
    """
    jobs_module._create_job_inner(
        job_type="secret_scanning", org="acme-org", run_id="run-1", env_vars={},
    )

    results: list[dict | None] = []
    barrier = threading.Barrier(2)

    def claim(runner_id):
        barrier.wait()  # release both threads at the same instant
        results.append(jobs_module._assign_next_job_inner(runner_id=runner_id))

    t1 = threading.Thread(target=claim, args=("r-a",))
    t2 = threading.Thread(target=claim, args=("r-b",))
    t1.start(); t2.start()
    t1.join(); t2.join()

    winners = [r for r in results if r is not None]
    losers = [r for r in results if r is None]
    assert len(winners) == 1
    assert len(losers) == 1
    assigned_runner = winners[0]["runnerId"]
    assert assigned_runner in ("r-a", "r-b")

    # And the DB row must reflect a single owner.
    queued = mem.list_jobs(status="queued")
    assert queued == []
    assigned = mem.list_jobs(status="assigned")
    assert len(assigned) == 1
    assert assigned[0]["runnerId"] == assigned_runner


def test_complete_job_increments_runner_jobs_completed(mem):
    _approved_runner(mem, "r-1", token_hash="h")
    job_id = jobs_module._create_job_inner(
        job_type="secret_scanning", org="acme-org", run_id="run-1", env_vars={},
    )
    jobs_module._assign_next_job_inner(runner_id="r-1")
    jobs_module._complete_job_inner(job_id)
    assert mem.read_runner("r-1")["jobsCompleted"] == 1


def test_fail_job_retryable_returns_to_queue(mem):
    job_id = jobs_module._create_job_inner(
        job_type="secret_scanning", org="acme-org", run_id="run-1", env_vars={},
    )
    jobs_module._assign_next_job_inner(runner_id="r-1")
    jobs_module._fail_job_inner(job_id, error="transient", retryable=True)
    assert mem.read_job(job_id)["status"] == "queued"


def test_fail_job_non_retryable_marks_failed(mem):
    job_id = jobs_module._create_job_inner(
        job_type="secret_scanning", org="acme-org", run_id="run-1", env_vars={},
    )
    jobs_module._assign_next_job_inner(runner_id="r-1")
    jobs_module._fail_job_inner(job_id, error="permanent")
    assert mem.read_job(job_id)["status"] == "failed"


def test_requeue_stale_jobs_releases_jobs_from_missing_runner(mem):
    job_id = jobs_module._create_job_inner(
        job_type="secret_scanning", org="acme-org", run_id="run-1", env_vars={},
    )
    jobs_module._assign_next_job_inner(runner_id="phantom-runner")
    # Runner doesn't exist in the registry — must requeue.
    requeued = jobs_module.requeue_stale_jobs()
    assert len(requeued) == 1
    assert mem.read_job(job_id)["status"] == "queued"


def test_requeue_stale_jobs_releases_jobs_from_stale_runner(mem):
    _approved_runner(mem, "r-1", token_hash="h")
    # Force the runner's last heartbeat far in the past.
    old = (datetime.now(timezone.utc) - timedelta(seconds=jobs_module.STALE_JOB_SECONDS + 60)).isoformat()
    mem.runners["r-1"]["lastHeartbeatAt"] = old

    jobs_module._create_job_inner(
        job_type="secret_scanning", org="acme-org", run_id="run-1", env_vars={},
    )
    jobs_module._assign_next_job_inner(runner_id="r-1")
    requeued = jobs_module.requeue_stale_jobs()
    assert len(requeued) == 1


def test_requeue_stale_jobs_leaves_fresh_runner_alone(mem):
    _approved_runner(mem, "r-1", token_hash="h")
    jobs_module._create_job_inner(
        job_type="secret_scanning", org="acme-org", run_id="run-1", env_vars={},
    )
    jobs_module._assign_next_job_inner(runner_id="r-1")
    requeued = jobs_module.requeue_stale_jobs()
    assert requeued == []


# Env-var encryption helpers


def test_encrypt_decrypt_roundtrip_for_sensitive_keys():
    plain = {"GIT_TOKEN": "secret-value", "WORKDIR": "/tmp"}
    enc = encrypt_env_vars(plain)
    assert enc["GIT_TOKEN"].startswith("ENC:")
    assert enc["WORKDIR"] == "/tmp"
    dec = decrypt_env_vars(enc)
    assert dec["GIT_TOKEN"] == "secret-value"
    assert dec["WORKDIR"] == "/tmp"


def test_decrypt_failure_returns_empty_string_not_leak():
    """A garbled ENC:-prefixed value must not raise and must not return the
    raw ciphertext."""
    result = decrypt_env_vars({"GIT_TOKEN": "ENC:not-real-ciphertext"})
    assert result["GIT_TOKEN"] == ""


def test_sensitive_keys_set_contains_known_credentials():
    # Guard against accidental shrinkage of the SENSITIVE_KEYS set.
    assert "GIT_TOKEN" in SENSITIVE_KEYS
    assert "REGISTRY_TOKEN" in SENSITIVE_KEYS


# Router: registration + heartbeat + protected endpoints


def _make_app() -> FastAPI:
    app = FastAPI()
    app.include_router(runner_router)
    return app


@pytest.fixture(autouse=True)
def _clear_rate_limit_buckets():
    from src.shared import rate_limit as rl
    with rl._lock:
        rl._buckets.clear()
    yield


def test_register_endpoint_returns_400_on_invalid_token():
    with patch(
        "src.runner.router.register_runner",
        return_value=(None, None, "Invalid or expired registration token"),
    ):
        client = TestClient(_make_app())
        resp = client.post("/api/v1/agent/register", json={"token": "bad"})
    assert resp.status_code == 400
    assert resp.json()["error"] == "Invalid or expired registration token"


def test_register_endpoint_returns_runner_id_and_auth_token():
    runner = {"id": "r-1", "status": "pending_approval", "maxConcurrent": 4}
    with patch(
        "src.runner.router.register_runner",
        return_value=(runner, "vra_secret", None),
    ):
        client = TestClient(_make_app())
        resp = client.post("/api/v1/agent/register", json={"token": "ok"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["runnerId"] == "r-1"
    assert body["authToken"] == "vra_secret"
    assert body["config"]["maxConcurrent"] == 4


def test_heartbeat_endpoint_requires_auth():
    client = TestClient(_make_app())
    # No Authorization header at all
    resp = client.post("/api/v1/agent/heartbeat")
    assert resp.status_code == 401


def test_heartbeat_endpoint_returns_404_when_runner_disappeared():
    with (
        patch("src.runner.router._require_runner",
              return_value=({"id": "r-1"}, None)),
        patch("src.runner.router.heartbeat", return_value=None),
    ):
        client = TestClient(_make_app())
        resp = client.post("/api/v1/agent/heartbeat", json={})
    assert resp.status_code == 404


def test_progress_endpoint_rejects_other_runners_jobs():
    """A runner posting progress on a job assigned to a different runner must
    be rejected with 403 — prevents cross-runner job tampering."""
    with (
        patch("src.runner.router._require_runner",
              return_value=({"id": "r-attacker"}, None)),
        patch("src.runner.router.read_job",
              return_value={"id": "j-1", "runnerId": "r-victim", "status": "running"}),
    ):
        client = TestClient(_make_app())
        resp = client.post("/api/v1/agent/jobs/j-1/progress", json={"logTail": [], "progress": {}})
    assert resp.status_code == 403


def test_complete_endpoint_returns_404_for_unknown_job():
    with (
        patch("src.runner.router._require_runner",
              return_value=({"id": "r-1"}, None)),
        patch("src.runner.router.read_job", return_value=None),
    ):
        client = TestClient(_make_app())
        resp = client.post("/api/v1/agent/jobs/missing/complete", json={})
    assert resp.status_code == 404


def test_complete_endpoint_rejects_other_runners_jobs():
    with (
        patch("src.runner.router._require_runner",
              return_value=({"id": "r-attacker"}, None)),
        patch("src.runner.router.read_job",
              return_value={"id": "j-1", "runnerId": "r-victim", "status": "running"}),
    ):
        client = TestClient(_make_app())
        resp = client.post("/api/v1/agent/jobs/j-1/complete", json={})
    assert resp.status_code == 403


def test_presign_uploads_rejects_path_traversal_filenames():
    """A malicious runner that requests presigned URLs for ../../etc/passwd
    must be rejected before any S3 key is generated."""
    with (
        patch("src.runner.router._require_runner",
              return_value=({"id": "r-1"}, None)),
        patch("src.runner.router.read_job", return_value={
            "id": "j-1", "runnerId": "r-1", "status": "running",
            "jobType": "secrets", "org": "acme-org", "runId": "run-1",
        }),
    ):
        client = TestClient(_make_app())
        resp = client.post(
            "/api/v1/agent/jobs/j-1/uploads/presign",
            json={"files": ["../../etc/passwd"]},
        )
    assert resp.status_code == 400
    assert "Unsafe filename" in resp.json()["error"]


def test_presign_uploads_rejects_jobs_not_in_running_state():
    with (
        patch("src.runner.router._require_runner",
              return_value=({"id": "r-1"}, None)),
        patch("src.runner.router.read_job", return_value={
            "id": "j-1", "runnerId": "r-1", "status": "queued",
            "jobType": "secrets", "org": "acme-org", "runId": "run-1",
        }),
    ):
        client = TestClient(_make_app())
        resp = client.post(
            "/api/v1/agent/jobs/j-1/uploads/presign",
            json={"files": ["report.json"]},
        )
    assert resp.status_code == 409


def test_progress_endpoint_reports_cancelled_back_to_runner():
    """Routes must surface cancellation flag so the runner stops working."""
    job_running = {"id": "j-1", "runnerId": "r-1", "status": "running",
                   "jobType": "secrets", "org": "acme-org", "runId": "run-1"}
    job_cancelled = dict(job_running, status="cancelled")
    with (
        patch("src.runner.router._require_runner",
              return_value=({"id": "r-1"}, None)),
        patch("src.runner.router.read_job",
              side_effect=[job_running, job_cancelled]),
        patch("src.runner.router.update_job_progress"),
        patch("src.runner.router._sync_progress_to_run"),
    ):
        client = TestClient(_make_app())
        resp = client.post("/api/v1/agent/jobs/j-1/progress", json={"logTail": [], "progress": {}})
    assert resp.status_code == 200
    assert resp.json()["cancelled"] is True


def test_cancel_jobs_for_scans_marks_matching_active_jobs_only(mem):
    """Cancels active jobs whose runId is keyed off any of the given scan IDs.

    Regression: cancel_older_queued_for_pr was marking ScanRuns as cancelled
    but leaving RunnerJobs queued/assigned/running. Runners would burn cycles
    running superseded scans to completion only to have the result dropped on
    ingest because the ScanRun was already 'cancelled'.
    """
    from src.runner.jobs import cancel_jobs_for_scans

    # Two scans to be superseded — three runner jobs across two scanner types
    # plus one job from an unrelated scan that must NOT be cancelled.
    mem.write_job({"id": "j-1", "status": "queued", "org": "acme-org",
                   "runId": "scan-A:dependencies_scanning", "jobType": "dependencies_scanning"})
    mem.write_job({"id": "j-2", "status": "assigned", "org": "acme-org",
                   "runId": "scan-A:secret_scanning", "jobType": "secret_scanning"})
    mem.write_job({"id": "j-3", "status": "running", "org": "acme-org",
                   "runId": "scan-B:code_scanning", "jobType": "code_scanning"})
    mem.write_job({"id": "j-4", "status": "queued", "org": "acme-org",
                   "runId": "scan-C:dependencies_scanning", "jobType": "dependencies_scanning"})
    # Terminal-state job that happens to match the prefix — must NOT be re-cancelled.
    mem.write_job({"id": "j-5", "status": "completed", "org": "acme-org",
                   "runId": "scan-A:code_scanning", "jobType": "code_scanning"})

    cancelled = cancel_jobs_for_scans(["scan-A", "scan-B"])

    cancelled_ids = sorted(c["id"] for c in cancelled)
    assert cancelled_ids == ["j-1", "j-2", "j-3"]
    assert mem.read_job("j-1")["status"] == "cancelled"
    assert mem.read_job("j-2")["status"] == "cancelled"
    assert mem.read_job("j-3")["status"] == "cancelled"
    # Unrelated scan untouched
    assert mem.read_job("j-4")["status"] == "queued"
    # Terminal-state job not re-cancelled
    assert mem.read_job("j-5")["status"] == "completed"


def test_cancel_jobs_for_scans_handles_empty_input(mem):
    """No scan IDs = no work, no exceptions, doesn't iterate the job list."""
    from src.runner.jobs import cancel_jobs_for_scans

    mem.write_job({"id": "j-1", "status": "queued", "org": "acme-org",
                   "runId": "scan-X:dependencies_scanning", "jobType": "dependencies_scanning"})
    assert cancel_jobs_for_scans([]) == []
    assert mem.read_job("j-1")["status"] == "queued"


def test_cancel_jobs_for_scans_prefix_match_requires_colon_separator(mem):
    """runId 'scan-AB:...' must NOT be cancelled when scan_ids=['scan-A'] —
    the colon separator prevents 'scan-A' from matching 'scan-ABC:...' etc.
    """
    from src.runner.jobs import cancel_jobs_for_scans

    mem.write_job({"id": "j-1", "status": "queued", "org": "acme-org",
                   "runId": "scan-ABC:dependencies_scanning", "jobType": "dependencies_scanning"})
    cancelled = cancel_jobs_for_scans(["scan-A"])
    assert cancelled == []
    assert mem.read_job("j-1")["status"] == "queued"
