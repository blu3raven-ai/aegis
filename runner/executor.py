# runner/executor.py
"""Docker execution: build docker run args, stream logs, collect output."""
from __future__ import annotations

import logging
import os
import re
import subprocess
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

logger = logging.getLogger(__name__)

WORKSPACE_DIR = Path(os.environ.get("RUNNER_WORKSPACE", "/workspace"))

from runner.image_manager import validate_image as _validate_image

_SAFE_JOB_ID = re.compile(r"^[a-zA-Z0-9_-]+$")


@dataclass
class ExecutionResult:
    exit_code: int | None
    job_dir: Path
    log_tail: list[str] = field(default_factory=list)
    container_name: str = ""


def _sanitize_job_id(job_id: str) -> str | None:
    """Validate and return job ID, or None if unsafe."""
    if not job_id or not _SAFE_JOB_ID.match(job_id):
        return None
    return job_id


def execute_docker_job(
    job: dict[str, Any],
    on_progress: Callable[[list[str], dict[str, Any]], None] | None = None,
    progress_interval: float = 5.0,
    cancel_event: threading.Event | None = None,
) -> ExecutionResult:
    """Execute a scanner Docker container for a job."""
    docker_image = job["dockerImage"]
    env_vars: dict[str, str] = job.get("dockerArgs", {}).get("envVars", {})
    job_id = job.get("jobId", "unknown")
    org = job.get("org", "unknown")
    run_id = job.get("runId", "unknown")

    safe_id = _sanitize_job_id(job_id)
    if not safe_id:
        logger.error("[!] Unsafe job ID rejected: %s", job_id)
        job_dir = WORKSPACE_DIR / "rejected"
        job_dir.mkdir(parents=True, exist_ok=True)
        return ExecutionResult(exit_code=126, job_dir=job_dir, log_tail=["ERROR: Unsafe job ID"])

    job_dir = WORKSPACE_DIR / safe_id
    job_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(job_dir, 0o777)

    if not _validate_image(docker_image):
        logger.error("[!] Blocked untrusted scanner image: %s", docker_image)
        return ExecutionResult(exit_code=126, job_dir=job_dir, log_tail=["ERROR: Untrusted scanner image blocked"])

    container_name = f"scan-{job.get('type', 'unknown')}-{run_id[:16]}"
    args: list[str] = ["docker", "run", "--name", container_name]

    args.extend([
        "--user", "1000:1000",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
    ])

    workspace_volume = os.environ.get("SCANNER_WORKSPACE_VOLUME", "runner-workspace")
    args.extend(["-v", f"{workspace_volume}:/scanner/output"])

    # Ensure scanner-user ownership on volumes on first use
    for vol_name in (workspace_volume, "vuln-scanner-grype-cache", "vuln-scanner-trivy-cache"):
        try:
            subprocess.run(
                ["docker", "run", "--rm", "-v", f"{vol_name}:/vol", "alpine",
                 "sh", "-c", "chown -R 1000:1000 /vol 2>/dev/null || true"],
                capture_output=True, timeout=10,
            )
        except Exception:
            pass
    args.extend(["-v", "vuln-scanner-grype-cache:/home/scanner/.cache/grype"])
    args.extend(["-v", "vuln-scanner-trivy-cache:/home/scanner/.cache/trivy"])

    network = os.environ.get("SCANNER_DOCKER_NETWORK", "")
    if network:
        args.extend(["--network", network])

    env_vars["JOB_ID"] = safe_id
    env_vars.setdefault("PYTHONUNBUFFERED", "1")
    for key, value in env_vars.items():
        args.extend(["-e", f"{key}={value}"])

    args.append(docker_image)
    log_tail: list[str] = []
    lock = threading.Lock()
    scanned_repos = 0
    finished_repos = 0
    current_repo: str | None = None
    current_classifying: str | None = None
    current_stage = "scanning"
    expected = job.get("expectedRepoCount") or 0

    last_progress_at = time.time()

    def handle_line(line: str) -> None:
        nonlocal log_tail, scanned_repos, finished_repos, current_repo, current_classifying, current_stage, last_progress_at
        clean = line.rstrip("\r\n")
        if not clean:
            return
        with lock:
            log_tail = (log_tail + [clean])[-120:]

            is_signal = False
            if "[+] Scanning repo:" in clean or "[+] Scanning image:" in clean:
                scanned_repos += 1
                parts = clean.split(":", 1)
                current_repo = parts[-1].strip() if len(parts) > 1 else None
                current_stage = "scanning"
                is_signal = True
            elif "[✓] Finished" in clean:
                finished_repos += 1
                current_repo = None
                is_signal = True
            elif "[classify]" in clean:
                current_stage = "classifying"
                # Extract "N/M" progress from "[classify] 123/456"
                _cls_parts = clean.split("[classify]", 1)
                if len(_cls_parts) > 1:
                    _cls_val = _cls_parts[1].strip()
                    if "/" in _cls_val:
                        current_classifying = _cls_val
                is_signal = True
            elif "Normalizing" in clean:
                current_stage = "ingesting"
                current_classifying = None
                is_signal = True

            now = time.time()
            if on_progress and (is_signal or (now - last_progress_at) >= progress_interval):
                last_progress_at = now
                on_progress(list(log_tail), {
                    "scannedRepos": scanned_repos,
                    "finishedRepos": finished_repos,
                    "currentRepo": current_repo,
                    "currentClassifying": current_classifying,
                    "stage": current_stage,
                })

    subprocess.run(["docker", "rm", "-f", container_name], capture_output=True, timeout=10)

    logger.info("[+] Docker command: %s", " ".join(args[:12]) + " ...")
    process = subprocess.Popen(
        args,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
    )

    def read_stream(stream: Any) -> None:
        if stream is None:
            return
        try:
            for line in stream:
                handle_line(line)
        finally:
            stream.close()

    stdout_thread = threading.Thread(target=read_stream, args=(process.stdout,), daemon=True)
    stderr_thread = threading.Thread(target=read_stream, args=(process.stderr,), daemon=True)
    stdout_thread.start()
    stderr_thread.start()

    try:
        while True:
            try:
                exit_code = process.wait(timeout=5)
                break
            except subprocess.TimeoutExpired:
                if cancel_event and cancel_event.is_set():
                    logger.info("[!] Cancellation requested — stopping container %s", container_name)
                    try:
                        subprocess.run(["docker", "stop", "-t", "5", container_name], capture_output=True, timeout=15)
                    except subprocess.TimeoutExpired:
                        logger.warning("[!] docker stop timed out — force killing")
                        subprocess.run(["docker", "kill", container_name], capture_output=True, timeout=5)
                    process.kill()
                    process.wait(timeout=10)
                    exit_code = 137
                    break
                if on_progress:
                    now = time.time()
                    if (now - last_progress_at) >= progress_interval:
                        last_progress_at = now
                        with lock:
                            on_progress(list(log_tail), {
                                "scannedRepos": scanned_repos,
                                "finishedRepos": finished_repos,
                                "currentRepo": current_repo,
                                "stage": "scanning",
                            })
    except Exception:
        process.kill()
        process.wait()
        exit_code = None

    stdout_thread.join(timeout=5)
    stderr_thread.join(timeout=5)

    if on_progress and exit_code != 137:
        with lock:
            on_progress(list(log_tail), {
                "scannedRepos": scanned_repos,
                "finishedRepos": finished_repos,
                "percent": 100 if exit_code == 0 else 0,
                "currentRepo": None,
                "stage": "completed" if exit_code == 0 else "failed",
            })

    try:
        subprocess.run(["docker", "rm", "-f", container_name], capture_output=True, timeout=10)
    except Exception:
        pass


    return ExecutionResult(
        exit_code=exit_code,
        job_dir=job_dir,
        log_tail=list(log_tail),
        container_name=container_name,
    )
