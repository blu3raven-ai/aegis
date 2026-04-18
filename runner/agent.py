# runner/agent.py
"""Main agent loop: heartbeat thread, job poll loop, orchestrates executor."""
from __future__ import annotations

import concurrent.futures
import json
import logging
import os
import shutil
import threading
from pathlib import Path
from typing import Any

import httpx

logger = logging.getLogger(__name__)

from runner.executor import execute_docker_job


CONFIG_PATH = Path.home() / ".vuln-runner" / "config.json"

HEARTBEAT_INTERVAL = 30  # seconds
POLL_INTERVAL = 5  # seconds

DEFAULT_MAX_CONCURRENT = 2


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

    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.auth_token}"}

    def _api(self, path: str) -> str:
        return f"{self.portal_url}/runner/api{path}"

    def _get_active_containers(self) -> list[dict[str, str]]:
        """Snapshot of active containers for heartbeat reporting."""
        snapshot = dict(self._active_jobs)  # copy to avoid concurrent-modification error
        return [
            {"name": f"scan-{jid[:8]}", "tool": info.get("tool", ""), "startedAt": info.get("startedAt", "")}
            for jid, info in snapshot.items()
        ]

    def heartbeat_loop(self) -> None:
        """Send heartbeat with system metrics every HEARTBEAT_INTERVAL seconds."""
        from runner.metrics import collect_metrics
        from runner.image_manager import check_all_images

        while not self._stop.is_set():
            try:
                metrics = collect_metrics()
                metrics["activeContainers"] = self._get_active_containers()
                metrics["scannerImages"] = check_all_images()

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

    def poll_and_execute(self) -> None:
        """Poll for jobs and execute concurrently up to _max_concurrent."""
        logger.info("[+] Agent started — polling %s (max %d concurrent)", self.portal_url, self._max_concurrent)
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
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
        logger.error("[!] Poll loop exited — agent is no longer processing jobs")

    def _poll_job(self) -> dict[str, Any] | None:
        """Poll for the next available job, skipping if disk space is low."""
        from runner.executor import WORKSPACE_DIR
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
        logger.info("[+] Executing job %s (%s) for %s", job_id, job_type, org)

        cancel_event = threading.Event()

        from datetime import datetime, timezone
        self._active_jobs[job_id] = {"tool": job_type, "startedAt": datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")}

        from runner.executor import WORKSPACE_DIR
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
            result = execute_docker_job(job, on_progress=on_progress, cancel_event=cancel_event)

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
                if cancel_event.is_set():
                    self._report_cancelled(job_id)
                else:
                    self._report_failure(job_id, "Scanner was killed unexpectedly (exit 137)")
                return

            if result.exit_code is not None and result.exit_code not in (0, 1, 2):
                logger.warning("[!] Scanner exited with code %s", result.exit_code)
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

            logger.info("[✓] Job %s completed (%d files uploaded)", job_id, uploaded)

        finally:
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

    def _cleanup_orphaned_containers(self) -> None:
        """Kill scanner containers left from a previous session."""
        import subprocess
        try:
            result = subprocess.run(
                ["docker", "ps", "-q", "--filter", "name=scan-"],
                capture_output=True, text=True, timeout=10,
            )
            container_ids = result.stdout.strip().splitlines()
            if container_ids:
                logger.info("[+] Cleaning up %d orphaned scanner container(s)", len(container_ids))
                subprocess.run(
                    ["docker", "rm", "-f"] + container_ids,
                    capture_output=True, timeout=30,
                )
        except Exception:
            pass

    def _cleanup_workspace(self) -> None:
        """Remove leftover job directories from a previous session."""
        from runner.executor import WORKSPACE_DIR
        if not WORKSPACE_DIR.exists():
            return
        for job_dir in WORKSPACE_DIR.iterdir():
            if job_dir.is_dir():
                logger.info("[+] Cleaning up orphaned job dir: %s", job_dir.name)
                shutil.rmtree(job_dir, ignore_errors=True)

    def _build_scanner_images(self) -> None:
        """Ensure all scanner images are available."""
        try:
            from runner.image_manager import build_missing_images
            statuses = build_missing_images()
            for scanner, status in statuses.items():
                logger.info("[+]   %s: %s", scanner, status)
        except Exception as e:
            logger.exception("[!] Scanner image build failed")

    def start(self) -> None:
        """Start the agent: cleanup, heartbeat thread, then poll loop."""
        self._cleanup_orphaned_containers()
        self._cleanup_workspace()

        hb_thread = threading.Thread(target=self.heartbeat_loop, daemon=True)
        hb_thread.start()

        build_thread = threading.Thread(target=self._build_scanner_images, daemon=True, name="scanner-build")
        build_thread.start()

        self.poll_and_execute()

    def stop(self) -> None:
        self._stop.set()
