# runner/agent.py
"""Main agent loop: heartbeat thread, job poll loop, routes jobs via dispatcher."""
from __future__ import annotations

import concurrent.futures
import json
import logging
import os
import shutil
import signal
import threading
import time
from pathlib import Path
from typing import Any

import httpx

from runner.metrics import (
    job_duration_seconds,
    job_pickup_latency_seconds,
    jobs_processed_total,
    start_metrics_server,
)
from runner.structured_logging import configure_logging, log_with_context
from runner.graceful_drain import GracefulDrainManager

logger = logging.getLogger(__name__)

from runner.dispatcher import get_scanner


WORKSPACE_DIR = Path(os.environ.get("RUNNER_WORKSPACE", "/workspace"))

CONFIG_PATH = Path.home() / ".vuln-runner" / "config.json"

HEARTBEAT_INTERVAL = 30  # seconds
POLL_INTERVAL = 5  # seconds

DEFAULT_MAX_CONCURRENT = 2

# Module-level agent instance — set by run_poll_loop()
# so that _pull_assignment() can operate on it without threading gymnastics.
_agent: RunnerAgent | None = None


def _setup_sigterm_handler() -> None:
    def _handle(signum, frame):  # noqa: ARG001
        logger.info("[+] SIGTERM received — shutting down")
        if _agent is not None:
            _agent.stop()

    try:
        signal.signal(signal.SIGTERM, _handle)
    except (OSError, ValueError):
        pass


def _should_stop() -> bool:
    return _agent is not None and _agent._stop.is_set()


def _pull_assignment() -> None:
    """Pull the next available job from the backend and submit it to the executor."""
    if _agent is None:
        return
    _agent._pull_and_dispatch()


def load_config() -> dict[str, Any]:
    """Load runner config from env vars or ~/.vuln-runner/config.json."""
    backend_url = os.environ.get("BACKEND_URL")
    registration_token = os.environ.get("RUNNER_REGISTRATION_TOKEN")

    if backend_url and registration_token:
        import platform
        name = os.environ.get("RUNNER_NAME", "runner")
        logger.info("[+] Registering with %s", backend_url)
        try:
            with httpx.Client(timeout=15.0) as client:
                resp = client.post(
                    f"{backend_url}/runner/api/register",
                    json={
                        "token": registration_token,
                        "name": name,
                        "os": platform.system().lower(),
                        "arch": platform.machine(),
                    },
                )
            if resp.status_code != 200:
                error = resp.json().get("error", resp.text)
                raise RuntimeError(f"Registration failed: {error}")

            data = resp.json()
            logger.info("[✓] Registered as %s (status: %s)", data["runnerId"], data["status"])
            config_data = data.get("config", {})
            return {
                "portalUrl": backend_url,
                "authToken": data["authToken"],
                "name": name,
                "maxConcurrent": config_data.get("maxConcurrent", 2),
            }

        except httpx.ConnectError:
            raise RuntimeError(f"Cannot reach backend at {backend_url} — is it running?")

    if not CONFIG_PATH.exists():
        raise FileNotFoundError(f"Runner not configured. Set BACKEND_URL + RUNNER_REGISTRATION_TOKEN env vars, or run: vuln-runner configure --url <URL> --token <TOKEN>")
    return json.loads(CONFIG_PATH.read_text(encoding="utf-8"))


def save_config(config: dict[str, Any]) -> None:
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    CONFIG_PATH.write_text(json.dumps(config, indent=2), encoding="utf-8")


class RunnerAgent:
    def __init__(self, config: dict[str, Any]) -> None:
        self.portal_url: str = config["portalUrl"].rstrip("/")
        self.auth_token: str = config["authToken"]
        self.name: str = config.get("name", "runner")
        self._stop = threading.Event()
        self._max_concurrent: int = config.get("maxConcurrent", DEFAULT_MAX_CONCURRENT)
        self._active_jobs: dict[str, dict] = {}  # job_id -> {tool, startedAt}
        self._pool: concurrent.futures.ThreadPoolExecutor | None = None
        self._futures: set[concurrent.futures.Future] = set()
        self._futures_lock = threading.Lock()
        self._drain = GracefulDrainManager(
            drain_timeout=int(os.getenv("RUNNER_DRAIN_TIMEOUT_SECONDS", "300"))
        )
        self._processed_total: int = 0
        self._processed_lock = threading.Lock()

    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.auth_token}"}

    def _api(self, path: str) -> str:
        return f"{self.portal_url}/runner/api{path}"

    def heartbeat_loop(self) -> None:
        """Send heartbeat with system metrics every HEARTBEAT_INTERVAL seconds."""
        from runner.metrics import collect_metrics

        while not self._stop.is_set():
            try:
                metrics = collect_metrics()

                with httpx.Client(timeout=10.0) as client:
                    resp = client.post(
                        self._api("/heartbeat"),
                        headers=self._headers(),
                        json=metrics,
                    )
                    if resp.status_code == 401:
                        logger.error("[!] Auth token rejected — re-register this runner")
                        self._stop.set()
                        return
                    if resp.status_code == 200:
                        data = resp.json()
                        config = data.get("config", {})
                        new_max = config.get("maxConcurrent")
                        if new_max and new_max != self._max_concurrent:
                            logger.info("[+] Config update: maxConcurrent %d → %d", self._max_concurrent, new_max)
                            self._max_concurrent = new_max

            except Exception as e:
                logger.warning("[!] Heartbeat failed: %s", e)
            self._stop.wait(HEARTBEAT_INTERVAL)

    def _reap_futures(self) -> None:
        """Remove completed futures and log any errors."""
        with self._futures_lock:
            done = {f for f in self._futures if f.done()}
            for f in done:
                try:
                    f.result()
                except Exception as e:
                    logger.error("[!] Job thread error: %s", e)
            self._futures -= done

    def _pull_and_dispatch(self) -> bool:
        """Pull the next job and submit it to the thread pool if capacity allows.

        Returns True if a job was dispatched, False otherwise.
        """
        if self._pool is None:
            return False

        # Refuse new work once a shutdown signal has been received
        if self._drain.is_draining():
            return False

        self._reap_futures()

        with self._futures_lock:
            active = len(self._futures)

        if active >= self._max_concurrent:
            return False

        try:
            job = self._poll_job()
            if job:
                with self._futures_lock:
                    self._futures.add(self._pool.submit(self._execute_job, job))
                return True
        except Exception as e:
            logger.warning("[!] Poll error: %s", e)
        return False

    def poll_and_execute(self) -> None:
        """Poll for jobs and execute concurrently up to _max_concurrent."""
        logger.info("[+] Agent started — polling %s (max %d concurrent)", self.portal_url, self._max_concurrent)
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
                self._pool = pool
                futures: set[concurrent.futures.Future] = set()
                while not self._stop.is_set():
                    try:
                        done = {f for f in futures if f.done()}
                        for f in done:
                            try:
                                f.result()
                            except Exception as e:
                                logger.error("[!] Job thread error: %s", e)
                        futures -= done

                        if len(futures) < self._max_concurrent:
                            try:
                                job = self._poll_job()
                                if job:
                                    futures.add(pool.submit(self._execute_job, job))
                                    continue
                            except Exception as e:
                                logger.warning("[!] Poll error: %s", e)
                    except Exception as e:
                        logger.exception("[!] Unexpected error in poll loop: %s", e)

                    self._stop.wait(POLL_INTERVAL)
        except Exception:
            logger.exception("[!] FATAL: poll_and_execute crashed")
        finally:
            self._pool = None
        logger.error("[!] Poll loop exited — agent is no longer processing jobs")

    def _poll_job(self) -> dict[str, Any] | None:
        """Poll for the next available job, skipping if disk space is low."""
        try:
            free_gb = shutil.disk_usage(WORKSPACE_DIR).free / (1024**3)
            if free_gb < 2.0:
                logger.warning("[!] Low disk space (%.1fGB free) — skipping poll", free_gb)
                return None
        except OSError:
            pass

        try:
            with httpx.Client(timeout=10.0) as client:
                resp = client.get(self._api("/jobs/next"), headers=self._headers())
                if resp.status_code == 204:
                    return None
                if resp.status_code == 403:
                    return None
                if resp.status_code == 401:
                    logger.error("[!] Auth token rejected")
                    self._stop.set()
                    return None
                if resp.status_code == 200:
                    return resp.json()
        except Exception as e:
            logger.warning("[!] Poll failed: %s", e)
        return None

    def _execute_job(self, job: dict[str, Any]) -> None:
        job_id = job["jobId"]
        org = job.get("org", "unknown")
        job_type = job.get("type", "dependencies")
        run_id = job.get("runId", "unknown")

        self._drain.track_job_start()
        log_with_context(
            logger, logging.INFO, "[+] Job assigned",
            job_id=job_id, scanner_type=job_type, run_id=run_id,
        )

        cancel_event = threading.Event()

        from datetime import datetime, timezone
        _job_start = time.monotonic()
        self._active_jobs[job_id] = {"tool": job_type, "startedAt": datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")}

        # Record pickup latency: time from job creation to runner pickup.
        _created_at = job.get("createdAt") or job.get("created_at") or ""
        if _created_at:
            try:
                _created_dt = datetime.fromisoformat(_created_at.replace("Z", "+00:00"))
                _pickup_latency = (datetime.now(timezone.utc) - _created_dt).total_seconds()
                _dispatch_mode = os.getenv("RUNNER_DISPATCH_MODE", "poll")
                job_pickup_latency_seconds.labels(
                    scanner_type=job_type, dispatch_mode=_dispatch_mode
                ).observe(max(0.0, _pickup_latency))
            except (ValueError, TypeError):
                pass

        from runner.streamer import ManifestStreamer, MAX_FINISH_WAIT
        from runner.uploader import upload_file

        job_dir = WORKSPACE_DIR / job_id

        streamer = ManifestStreamer(
            job_dir=job_dir,
            upload_fn=upload_file,
            tool=job_type,
            org=org,
            run_id=run_id,
        )

        streamer_thread = threading.Thread(
            target=streamer.run, daemon=True, name=f"streamer-{job_id[:12]}",
        )
        streamer_thread.start()

        def on_progress(log_tail, progress):
            try:
                with httpx.Client(timeout=10.0) as client:
                    resp = client.post(
                        self._api(f"/jobs/{job_id}/progress"),
                        headers=self._headers(),
                        json={
                            "logTail": log_tail[-50:],
                            "progress": {
                                **progress,
                                **streamer.get_progress(),
                            },
                        },
                    )
                    if resp.status_code == 200 and resp.json().get("cancelled"):
                        logger.info("[!] Job %s cancelled by user — killing container", job_id)
                        cancel_event.set()
            except Exception:
                pass

        try:
            scanner = get_scanner(job_type)
            result = scanner.run_scan(job, job_dir=job_dir, on_progress=on_progress, cancel_event=cancel_event)

            streamer.done_event.set()

            if not streamer.finished_event.wait(timeout=MAX_FINISH_WAIT):
                logger.warning("[!] Streamer still uploading after %ds — extending wait", MAX_FINISH_WAIT)
                if not streamer.finished_event.wait(timeout=MAX_FINISH_WAIT):
                    logger.error("[!] Streamer timed out after %ds — proceeding with %d files uploaded",
                                 MAX_FINISH_WAIT * 2, streamer.uploaded_count)

            uploaded = streamer.uploaded_count
            failed = streamer.failed_count
            if uploaded > 0:
                logger.info("[✓] Uploaded %d files to MinIO (%d failed)", uploaded, failed)

            # 137 = SIGKILL — distinguish user cancellation from unexpected kill
            if result.exit_code == 137:
                jobs_processed_total.labels(scanner_type=job_type, status="failed").inc()
                job_duration_seconds.labels(scanner_type=job_type).observe(time.monotonic() - _job_start)
                if cancel_event.is_set():
                    self._report_cancelled(job_id)
                else:
                    log_with_context(
                        logger, logging.ERROR, "[!] Job failed — scanner killed",
                        job_id=job_id, scanner_type=job_type, exit_code=137,
                    )
                    self._report_failure(job_id, "Scanner was killed unexpectedly (exit 137)")
                return

            if result.exit_code is not None and result.exit_code not in (0, 1, 2):
                log_with_context(
                    logger, logging.WARNING, "[!] Job failed — unexpected exit code",
                    job_id=job_id, scanner_type=job_type, exit_code=result.exit_code,
                )
                jobs_processed_total.labels(scanner_type=job_type, status="failed").inc()
                job_duration_seconds.labels(scanner_type=job_type).observe(time.monotonic() - _job_start)
                self._report_failure(job_id, f"Scanner exited with code {result.exit_code}")
                return

            try:
                with httpx.Client(timeout=30.0) as client:
                    resp = client.post(
                        self._api(f"/jobs/{job_id}/complete"),
                        headers=self._headers(),
                        json={"filesUploaded": uploaded, "filesFailed": failed},
                    )
                    if resp.status_code == 200:
                        data = resp.json()
                        new_token = data.get("newAuthToken")
                        if new_token:
                            self.auth_token = new_token
                            if CONFIG_PATH.exists():
                                try:
                                    cfg = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
                                    cfg["authToken"] = new_token
                                    save_config(cfg)
                                except Exception:
                                    pass
            except Exception as e:
                logger.error("[!] Failed to report completion: %s", e)

            jobs_processed_total.labels(scanner_type=job_type, status="success").inc()
            job_duration_seconds.labels(scanner_type=job_type).observe(time.monotonic() - _job_start)
            with self._processed_lock:
                self._processed_total += 1
            log_with_context(
                logger, logging.INFO, "[✓] Job completed",
                job_id=job_id, scanner_type=job_type,
                files_uploaded=uploaded, duration_seconds=round(time.monotonic() - _job_start, 2),
            )

        finally:
            self._drain.track_job_end()
            streamer.done_event.set()
            if not streamer.finished_event.wait(timeout=MAX_FINISH_WAIT):
                logger.warning("[!] Streamer did not finish within %ds during cleanup — proceeding", MAX_FINISH_WAIT)
            self._active_jobs.pop(job_id, None)
            if job_dir.exists():
                shutil.rmtree(job_dir, ignore_errors=True)

    def _report_cancelled(self, job_id: str) -> None:
        try:
            with httpx.Client(timeout=10.0) as client:
                client.post(
                    self._api(f"/jobs/{job_id}/fail"),
                    headers=self._headers(),
                    json={"error": "Scan cancelled by user", "cancelled": True},
                )
        except Exception:
            pass
        logger.info("[+] Job %s cancelled by user", job_id)

    def _report_failure(self, job_id: str, error: str) -> None:
        try:
            with httpx.Client(timeout=10.0) as client:
                client.post(
                    self._api(f"/jobs/{job_id}/fail"),
                    headers=self._headers(),
                    json={"error": error},
                )
        except Exception:
            pass
        logger.error("[!] Job %s failed: %s", job_id, error)

    def _cleanup_workspace(self) -> None:
        """Remove leftover job directories from a previous session."""
        if not WORKSPACE_DIR.exists():
            return
        for job_dir in WORKSPACE_DIR.iterdir():
            if job_dir.is_dir():
                logger.info("[+] Cleaning up orphaned job dir: %s", job_dir.name)
                shutil.rmtree(job_dir, ignore_errors=True)

    def start(self) -> None:
        """Start the agent: configure logging, install drain handler, cleanup,
        heartbeat thread, then main loop.

        The main loop is selected by RUNNER_DISPATCH_MODE (default: poll).
        """
        configure_logging()
        self._drain.install_handler()

        self._cleanup_workspace()

        start_metrics_server()

        hb_thread = threading.Thread(target=self.heartbeat_loop, daemon=True)
        hb_thread.start()

        self.poll_and_execute()

    def stop(self) -> None:
        self._stop.set()
        self._drain.trigger_drain()
        drained = self._drain.wait_for_drain()
        if not drained:
            logger.warning("[!] Drain timeout reached — exiting with in-flight jobs still running")


# ---------------------------------------------------------------------------
# Module-level API consumed by tests and the mode dispatcher
# ---------------------------------------------------------------------------

def run_poll_loop() -> None:
    """Start the agent in poll mode (original behaviour, default)."""
    global _agent
    _setup_sigterm_handler()
    config = load_config()
    _agent = RunnerAgent(config)
    _agent.start()


