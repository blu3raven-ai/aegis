from __future__ import annotations

import hashlib
import json
import logging
import re
import threading
import time
from copy import deepcopy
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock
from typing import Any, Literal

import os

import src.storage as storage
from src.secrets.lifecycle import secrets_hooks
from src.secrets.pool import (
    get_scan_start_date,
    merge_pool,
)
from src.shared.config import get_scan_sources_for_org, get_secret_scanner_config
from src.shared.object_store import (
    download_bytes,
    list_objects,
    tag_object,
)
from src.shared.lifecycle import ScanContext, apply_lifecycle as _apply_lifecycle
from src.shared.paths import normalize_org
from src.secrets.store import ensure_secret_identity
from src.storage import (
    create_secret_run,
    default_secret_run_progress,
    read_latest_findings,
    read_secret_run,
    update_secret_run,
)

ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
_TEMP_PREFIX_RE = re.compile(r"^/tmp/tmp\.[^/]+/")
SCANNING_RE = re.compile(r"\[\+\]\s+Scanning (?:repo|image):\s+(\S+?)(?:\s+\(.*\))?$")
FINISHED_RE = re.compile(r"\[✓\]\s+Finished(?:\s+scanning)?\s+(\S+?)(?:\s+—.*)?$")
CLASSIFY_RE = re.compile(r"\[classify\]\s+(\d+/\d+)")
INGESTING_RE = "Normalizing results"
logger = logging.getLogger(__name__)


@dataclass
class ScanProgressState:
    scanned_repos: set[str] = field(default_factory=set)
    finished_repos: set[str] = field(default_factory=set)
    current_repo: str | None = None
    current_classifying: str | None = None
    stage: str = "queued"


def strip_ansi(line: str) -> str:
    return ANSI_RE.sub("", line)


def strip_temp_prefix(path: str | None) -> str | None:
    """Strip /tmp/tmp.*/ prefix so stored paths are repo-relative."""
    if not path:
        return path
    return _TEMP_PREFIX_RE.sub("", path) or path


def extract_repo_progress(line: str) -> dict[str, str | None] | None:
    scanning_match = SCANNING_RE.search(line)
    if scanning_match:
        return {"type": "scanning", "repo": scanning_match.group(1)}

    finished_match = FINISHED_RE.search(line)
    if finished_match:
        return {"type": "finished", "repo": finished_match.group(1)}

    if INGESTING_RE in line:
        return {"type": "ingesting", "repo": None}

    classify_match = CLASSIFY_RE.search(line)
    if classify_match:
        return {"type": "classifying", "progress": classify_match.group(1)}

    return None


def observe_scan_progress_line(state: ScanProgressState, line: str) -> bool:
    clean_line = strip_ansi(line)
    signal = extract_repo_progress(clean_line)
    if not signal:
        return False

    if signal["type"] == "scanning" and signal["repo"]:
        state.scanned_repos.add(signal["repo"])
        state.current_repo = signal["repo"]
        state.stage = "scanning"
    elif signal["type"] == "finished" and signal["repo"]:
        state.finished_repos.add(signal["repo"])
        if state.current_repo == signal["repo"]:
            state.current_repo = None
        state.stage = "scanning"
    elif signal["type"] == "classifying":
        state.current_classifying = signal["progress"]
        state.stage = "classifying"
    elif signal["type"] == "ingesting":
        state.current_repo = None
        state.current_classifying = None
        state.stage = "ingesting"
    return True


def summarize_scan_progress(state: ScanProgressState, fallback: dict[str, Any]) -> dict[str, Any]:
    scanned_repos = max(int(fallback.get("scannedRepos") or 0), len(state.scanned_repos))
    finished_repos = max(int(fallback.get("finishedRepos") or 0), len(state.finished_repos))
    expected_repos = reconcile_expected_repos(
        fallback.get("expectedRepos"),
        scanned_repos,
        finished_repos,
    )
    return {
        **fallback,
        "expectedRepos": expected_repos,
        "scannedRepos": scanned_repos,
        "finishedRepos": finished_repos,
        "currentRepo": state.current_repo,
        "currentClassifying": state.current_classifying,
        "stage": state.stage,
    }


LOG_TAIL_LIMIT = 120


@dataclass
class RuntimeJob:
    org: str
    run_id: str
    container_name: str | None = None
    child_pid: int | None = None


class InMemoryScanRuntime:
    def __init__(self) -> None:
        self._jobs: dict[str, RuntimeJob] = {}
        self._cancelled: set[str] = set()
        self._released_run_ids: dict[str, str] = {}
        self._lock = Lock()

    def _key(self, org: str) -> str:
        return org.strip().lower()

    def start(self, org: str, run_id: str) -> bool:
        key = self._key(org)
        with self._lock:
            if key in self._jobs:
                return False
            self._released_run_ids.pop(key, None)
            self._jobs[key] = RuntimeJob(org=org, run_id=run_id)
            self._cancelled.discard(run_id)
            return True

    def set_process_meta(self, org: str, *, container_name: str | None = None, child_pid: int | None = None) -> None:
        key = self._key(org)
        with self._lock:
            job = self._jobs.get(key)
            if not job:
                return
            if container_name is not None:
                job.container_name = container_name
            if child_pid is not None:
                job.child_pid = child_pid

    def cancel(self, org: str, cancel_fn: Any | None = None) -> dict[str, Any]:
        key = self._key(org)
        with self._lock:
            job = self._jobs.get(key)
            if not job:
                return {"ok": False, "reason": "no_active_run"}
            self._cancelled.add(job.run_id)

        try:
            if cancel_fn:
                cancel_fn(job)
            return {"ok": True, "runId": job.run_id}
        finally:
            with self._lock:
                current = self._jobs.get(key)
                if current and current.run_id == job.run_id:
                    self._jobs.pop(key, None)
                self._released_run_ids[key] = job.run_id

    def is_cancelled(self, run_id: str) -> bool:
        with self._lock:
            return run_id in self._cancelled

    def release(self, org: str) -> None:
        key = self._key(org)
        with self._lock:
            job = self._jobs.pop(key, None)
            if job:
                self._cancelled.discard(job.run_id)
            released_run_id = self._released_run_ids.pop(key, None)
            if released_run_id:
                self._cancelled.discard(released_run_id)

    def probe(self, org: str) -> dict[str, Any]:
        with self._lock:
            job = self._jobs.get(self._key(org))
            if not job:
                return {"active": False, "runId": None, "containerName": None, "childPid": None}
            return {
                "active": True,
                "runId": job.run_id,
                "containerName": job.container_name,
                "childPid": job.child_pid,
            }


def keep_tail(lines: list[str], chunk: str, limit: int = LOG_TAIL_LIMIT) -> list[str]:
    next_lines = [*lines, *[line for line in re.split(r"\r?\n", chunk) if line]]
    return next_lines[-limit:]


def compute_running_percent(expected_repos: int | None, scanned_repos: int, finished_repos: int) -> float:
    expected_repos = reconcile_expected_repos(expected_repos, scanned_repos, finished_repos)
    if expected_repos and expected_repos > 0:
        return min(94, max(2 if finished_repos > 0 else 1, (finished_repos / expected_repos) * 94))

    denominator = max(scanned_repos, 1)
    return min(90, max(4 if finished_repos > 0 else 2, (finished_repos / denominator) * 85))


def reconcile_expected_repos(expected_repos: Any, scanned_repos: int, finished_repos: int) -> int | None:
    expected = int(expected_repos) if isinstance(expected_repos, (int, float)) else 0
    reconciled = max(expected, int(scanned_repos or 0), int(finished_repos or 0))
    return reconciled or None




def parse_progress_from_lines(lines: list[str], fallback: dict[str, Any]) -> dict[str, Any]:
    state = ScanProgressState(
        current_repo=fallback.get("currentRepo"),
        current_classifying=fallback.get("currentClassifying"),
        stage=fallback.get("stage") or "queued",
    )
    for line in lines:
        observe_scan_progress_line(state, line)
    return summarize_scan_progress(state, fallback)


MAX_JSONL_SIZE_MB = 100
MAX_JSONL_LINES = 500_000


def as_record(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def pick_string(record: dict[str, Any], keys: list[str]) -> str | None:
    for key in keys:
        value = record.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def nested(record: dict[str, Any], path: list[str]) -> Any:
    current: Any = record
    for segment in path:
        if not isinstance(current, dict):
            return None
        current = current.get(segment)
    return current


def safe_iso(value: str | None) -> str | None:
    if not value:
        return None
    try:
        normalized = value.replace("Z", "+00:00")
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def build_fingerprint(parts: list[str | None]) -> str:
    normalized = "::".join(part or "" for part in parts)
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def _line_value(raw: dict[str, Any]) -> int | None:
    value = nested(raw, ["SourceMetadata", "Data", "Git", "line"])
    if isinstance(value, bool):
        pass
    elif isinstance(value, (int, float)):
        return int(value)

    fs_value = nested(raw, ["SourceMetadata", "Data", "Filesystem", "line"])
    if isinstance(fs_value, bool):
        pass
    elif isinstance(fs_value, (int, float)):
        return int(fs_value)

    for key in ["line", "StartLine"]:
        candidate = raw.get(key)
        if isinstance(candidate, bool):
            continue
        if isinstance(candidate, (int, float)):
            return int(candidate)
    return None


_VALID_AI_CLASSIFICATIONS = {"likely_real", "false_positive", "uncertain", "likely_false_positive"}

# Maps AI classification labels to (stored_value, confidence).
# Uncertain has no confidence score since no determination was made.
_AI_TO_BINARY: dict[str, tuple[str, float | None]] = {
    "likely_real":           ("likely_secret", 0.80),
    "false_positive":        ("not_secret",    0.80),
    "likely_false_positive": ("not_secret",    0.80),
    "uncertain":             ("uncertain",     None),
}


def build_classification_entries(
    raw: dict[str, Any],
    run_id: str,
    scan_depth: str | None,
    scanned_at: str,
) -> list[dict[str, Any]]:
    """Build classification entries from raw scanner output."""
    entries: list[dict[str, Any]] = []
    source = (raw.get("source") or "").lower()

    if source == "trufflehog":
        verified = raw.get("Verified")
        value = "verified_secret" if verified is True else "uncertain"
        confidence: float | None = 1.0 if verified is True else None
        entries.append({
            "value": value,
            "source": "scanner",
            "scanDepth": scan_depth,
            "confidence": confidence,
            "runId": run_id,
            "scannedAt": scanned_at,
        })

    ai_class = raw.get("ai_classification")
    if ai_class in _VALID_AI_CLASSIFICATIONS:
        stored_value, fallback_confidence = _AI_TO_BINARY[ai_class]
        # Use model probability if available, else default (0.80); uncertain always null
        raw_score = raw.get("ai_confidence")
        if stored_value == "uncertain":
            ai_confidence: float | None = None
        elif isinstance(raw_score, (int, float)) and 0.0 <= raw_score <= 1.0:
            ai_confidence = round(float(raw_score), 4)
        else:
            ai_confidence = fallback_confidence
        entries.append({
            "value": stored_value,
            "source": "ai",
            "scanDepth": scan_depth,
            "confidence": ai_confidence,
            "runId": run_id,
            "scannedAt": scanned_at,
        })

    return entries


def normalize_finding(run_id: str, org: str, raw: dict[str, Any], scan_depth: str | None = "light") -> dict[str, Any]:
    source = pick_string(raw, ["source"]) or "unknown"
    repository = pick_string(raw, ["repository", "Repo", "repo"]) or "unknown"
    detector = pick_string(raw, ["DetectorName", "DetectorType", "RuleID", "rule", "name", "Title"]) or "unknown"
    snippet = pick_string(raw, ["Raw", "Match", "match", "secret", "Secret", "Redacted"]) or "[redacted]"
    git = as_record(nested(raw, ["SourceMetadata", "Data", "Git"]))
    filesystem = as_record(nested(raw, ["SourceMetadata", "Data", "Filesystem"]))
    file_path = strip_temp_prefix(
        pick_string(raw, ["File", "path", "Path", "file"])
        or pick_string(git, ["file"])
        or pick_string(filesystem, ["file"])
    )
    commit = pick_string(raw, ["Commit", "commit", "commitHash"]) or pick_string(git, ["commit"])
    line_value = _line_value(raw)
    detected_at = (
        safe_iso(pick_string(raw, ["Date", "detectedAt", "timestamp", "date", "CreatedAt"]))
        or safe_iso(pick_string(git, ["timestamp"]))
        or now_iso()
    )
    fingerprint = build_fingerprint(
        [
            org.lower(),
            repository.lower(),
            source.lower(),
            detector.lower(),
            file_path.lower() if file_path else None,
            str(line_value or ""),
            commit.lower() if commit else None,
            snippet,
        ]
    )
    finding = {
        "id": f"{run_id}:{fingerprint}",
        "runId": run_id,
        "organization": org.lower(),
        "repository": repository,
        "source": source,
        "detector": detector,
        "secretSnippet": snippet,
        "filePath": file_path,
        "line": line_value,
        "commit": commit,
        "detectedAt": detected_at,
        "fingerprint": fingerprint,
        "secretIdentity": None,
        "reviewStatus": "new",
        "classificationHistory": build_classification_entries(raw, run_id, scan_depth, now_iso()),
        "aiReasoning": raw.get("ai_reasoning") or None,
        "raw": raw,
    }
    result = ensure_secret_identity(finding)
    result.setdefault("reviewStatus", "new")
    return result


def _repo_to_latest_sha_from_list(findings: list[dict[str, Any]]) -> dict[str, str | None]:
    """Extract repo->latest commit SHA from a list of findings."""
    latest_by_repo: dict[str, tuple[str, str | None]] = {}
    for finding in findings:
        repo = str(finding.get("repository") or "").strip()
        if not repo:
            continue
        detected_at = finding.get("detectedAt") or ""
        commit = finding.get("commit")
        commit_sha = str(commit).strip() if isinstance(commit, str) and commit.strip() else None
        current = latest_by_repo.get(repo)
        if current is None or detected_at > current[0]:
            latest_by_repo[repo] = (detected_at, commit_sha)
    return {repo: sha for repo, (_, sha) in latest_by_repo.items()}


def ingest_findings(
    org: str,
    run_id: str,
    raw_findings: list[dict[str, Any]],
    scan_depth: str | None = "light",
    source_type: str | None = None,
) -> tuple[dict[str, Any] | None, dict[str, str | None] | None]:
    """Normalize, deduplicate, and apply lifecycle. Returns (None, repo_to_sha)."""
    findings = [normalize_finding(run_id, org, finding, scan_depth) for finding in raw_findings]

    # Default-exclude archived rows: archived findings are retired from the
    # active pool, so a re-detected match should be treated as a fresh finding
    # rather than resurrecting the archived row.
    previous = read_latest_findings(org)
    merged = merge_pool(findings, previous)
    ctx = ScanContext(tool="secrets", org=org, run_id=run_id, source_type=source_type)
    new_findings = _apply_lifecycle(secrets_hooks, ctx, merged)

    try:
        from src.settings.llm_usage import record_usage_from_findings
        record_usage_from_findings(merged)
    except Exception:
        logger.warning("Failed to record LLM usage from secrets ingest", exc_info=True)

    if new_findings:
        try:
            from src.notifications.emitter import notify_new_critical_findings
            notify_new_critical_findings("secrets", org, new_findings)
        except Exception:
            import logging
            logging.getLogger(__name__).warning("Failed to emit new finding notifications", exc_info=True)

        from src.shared.event_emit_helpers import emit_finding_created
        for finding in new_findings:
            emit_finding_created(
                finding=finding,
                scanner_type="secrets",
                source_component="secrets.scanner",
            )

    repo_to_sha = _repo_to_latest_sha_from_list(merged)
    return None, repo_to_sha


def ingest_normalized_jsonl(
    org: str,
    run_id: str,
    normalized_jsonl_path: Path | str,
) -> tuple[dict[str, Any] | None, dict[str, str | None] | None]:
    path = Path(normalized_jsonl_path)
    stats = path.stat()
    max_bytes = MAX_JSONL_SIZE_MB * 1024 * 1024
    if stats.st_size > max_bytes:
        raise ValueError(f"Normalized JSONL file too large ({round(stats.st_size / 1024 / 1024)}MB > {MAX_JSONL_SIZE_MB}MB limit)")

    lines = path.read_text(encoding="utf-8").splitlines()
    if len(lines) > MAX_JSONL_LINES:
        raise ValueError(f"Too many lines in JSONL file ({len(lines)} > {MAX_JSONL_LINES} limit)")

    raw_findings = [as_record(json.loads(line.strip())) for line in lines if line.strip()]
    return ingest_findings(org, run_id, raw_findings[:MAX_JSONL_LINES])


def scanner_finding_source(file_name: str) -> str | None:
    if file_name == "trufflehog.json":
        return "trufflehog"
    return None


def parse_scanner_finding_payload(raw: str) -> list[dict[str, Any]]:
    trimmed = raw.strip()
    if not trimmed:
        return []
    try:
        parsed = json.loads(trimmed)
        if isinstance(parsed, list):
            return [as_record(item) for item in parsed]
        return [as_record(parsed)]
    except json.JSONDecodeError:
        pass

    return [as_record(json.loads(line.strip())) for line in trimmed.splitlines() if line.strip()]


def read_raw_scanner_findings(org: str, raw_org_output_dir: Path | str) -> list[dict[str, Any]]:
    base = Path(raw_org_output_dir)
    findings: list[dict[str, Any]] = []
    if not base.exists():
        return findings

    for repo_dir in base.iterdir():
        if not repo_dir.is_dir():
            continue
        for file_path in repo_dir.iterdir():
            if not file_path.is_file():
                continue
            source = scanner_finding_source(file_path.name)
            if not source:
                continue
            records = parse_scanner_finding_payload(file_path.read_text(encoding="utf-8"))
            for record in records:
                findings.append({**record, "organization": org, "repository": repo_dir.name, "source": source})
    return findings


def ingest_raw_scanner_output(
    org: str,
    run_id: str,
    raw_org_output_dir: Path | str,
    scan_depth: str | None = "light",
) -> tuple[dict[str, Any] | None, dict[str, str | None] | None]:
    return ingest_findings(org, run_id, read_raw_scanner_findings(org, raw_org_output_dir), scan_depth)


SecretRunStatus = Literal[
    "queued",
    "running",
    "ingesting",
    "completed",
    "completed_with_merge_error",
    "failed",
    "cancelled",
]

TRANSITIONS: dict[SecretRunStatus, set[SecretRunStatus]] = {
    "queued": {"running", "cancelled", "failed"},
    "running": {"ingesting", "cancelled", "failed"},
    "ingesting": {"completed", "completed_with_merge_error", "cancelled", "failed"},
    "completed": set(),
    "completed_with_merge_error": set(),
    "failed": set(),
    "cancelled": set(),
}


def can_transition_run_status(from_status: str, to_status: str) -> bool:
    if from_status == to_status:
        return True
    return to_status in TRANSITIONS.get(from_status, set())


def apply_run_transition(current: dict[str, Any], next_status: str, patch: dict[str, Any] | None = None) -> dict[str, Any] | None:
    if not can_transition_run_status(str(current.get("status") or ""), next_status):
        return None

    timestamp = now_iso()
    next_run = deepcopy(current)
    if patch:
        next_run.update(patch)
    next_run["status"] = next_status
    next_run["lastStatusTransitionAt"] = timestamp
    next_run["lastHeartbeatAt"] = (patch or {}).get("lastHeartbeatAt") or timestamp
    return next_run


MAX_SCAN_DURATION_SECONDS = 12 * 60 * 60
RUN_UPDATE_INTERVAL_SECONDS = 1.2


def _execute_via_runner(
    org: str,
    run_id: str,
    config: dict[str, str],
    repo_urls: str,
    token: str,
    scan_depth: str = "light",
    scan_start_date: str | None = None,
) -> dict[str, Any] | None:
    """Create a runner job and poll until completion."""
    from src.runner.jobs import create_job, read_job

    env_vars = {
        "GIT_TOKEN": token,
        "GIT_REPOS": repo_urls,
        "ORG_LABEL": org,
        "RUN_ID": run_id,
        "CONCURRENCY": config.get("concurrency") or "4",
        "SCAN_DEPTH": scan_depth,
    }
    if scan_start_date:
        env_vars["SCAN_START_DATE"] = scan_start_date

    job = create_job(
        job_type="secrets",
        org=org,
        run_id=run_id,
        env_vars=env_vars,
        expected_repo_count=len(repo_urls.split(",")) if repo_urls else 0,
    )

    timeout = MAX_SCAN_DURATION_SECONDS
    start = time.time()
    while time.time() - start < timeout:
        current = read_job(job["id"])
        if not current:
            break
        if current["status"] in ("completed", "failed", "cancelled"):
            return current
        time.sleep(5)

    return None


def _transition_run(org: str, run_id: str, status: str, patch: dict) -> dict | None:
    current = read_secret_run(org, run_id)
    if not current:
        return None
    transitioned = apply_run_transition(
        current,
        status,
        {**patch, "reconciled": patch.get("reconciled", False), "reconciliationReason": patch.get("reconciliationReason")},
    )
    if not transitioned:
        return current
    return update_secret_run(org, run_id, transitioned)



def mark_run_cancelled(org: str, run_id: str) -> dict | None:
    current = read_secret_run(org, run_id) or create_secret_run(org, run_id)
    progress = current.get("progress") if isinstance(current.get("progress"), dict) else default_secret_run_progress()
    cancelled = _transition_run(
        org,
        run_id,
        "cancelled",
        {
            "finishedAt": now_iso(),
            "error": "Cancelled by user",
            "reconciled": False,
            "reconciliationReason": None,
            "progress": {
                "expectedRepos": progress.get("expectedRepos"),
                "scannedRepos": progress.get("scannedRepos") or 0,
                "finishedRepos": progress.get("finishedRepos") or 0,
                "percent": progress.get("percent") or 0,
                "currentRepo": None,
                "stage": "cancelled",
            },
        },
    )
    return cancelled


def ingest_secrets_from_minio(org: str, run_id: str, source_type: str | None = None) -> None:
    """Ingest secret scan results from object store after runner completion."""
    from src.shared.object_store import find_findings_jsonl

    data = find_findings_jsonl(f"secrets/{org}/{run_id}/")
    if data is None:
        logger.warning("No secrets output for %s/%s", org, run_id)
        update_secret_run(org, run_id, {
            "status": "failed", "finishedAt": now_iso(),
            "error": "No output files found",
        })
        return

    lines = data.decode("utf-8").splitlines()
    raw_findings = [json.loads(line) for line in lines if line.strip()]

    # Skip lifecycle on empty results — could be scanner errors, not truly 0 findings
    if raw_findings:
        ingest_findings(org, run_id, raw_findings, source_type=source_type)

    update_secret_run(org, run_id, {
        "status": "completed",
        "finishedAt": now_iso(),
        "findingsCount": len(raw_findings),
        "progress": {"percent": 100, "stage": "completed"},
    })


def execute_secret_scan_once(
    org: str,
    token: str,
    run_id: str,
    *,
    source_type: str | None = None,
    expected_repos: int | None = None,
    scanner_config: dict[str, str] | None = None,
    runtime: InMemoryScanRuntime | None = None,
    scan_depth: str | None = None,
) -> dict | None:
    runtime_started = runtime.start(org, run_id) if runtime else False
    if runtime and not runtime_started:
        return None

    if not read_secret_run(org, run_id):
        create_secret_run(org, run_id)

    sources = get_scan_sources_for_org(org)
    repo_sources = [s for s in sources if s.repo_urls]

    if not repo_sources:
        _transition_run(
            org, run_id, "completed",
            {"finishedAt": now_iso(), "error": None, "findingsCount": 0,
             "progress": {"expectedRepos": 0, "scannedRepos": 0, "finishedRepos": 0, "percent": 100, "currentRepo": None, "stage": "completed"}},
        )
        if runtime and runtime_started:
            runtime.release(org)
        return read_secret_run(org, run_id)

    update_secret_run(org, run_id, {"sourceCategory": "code-repositories"})

    total_repo_count = sum(len(s.repo_urls) for s in repo_sources)
    resolved_expected_repos = expected_repos if expected_repos is not None else (total_repo_count or None)

    update_secret_run(org, run_id, {
            "progress": {
                "expectedRepos": resolved_expected_repos,
                "scannedRepos": 0,
                "finishedRepos": 0,
                "percent": 0,
                "currentRepo": None,
                "stage": "scanning",
            },
        },
    )

    config = scanner_config or get_secret_scanner_config()
    resolved_scan_depth = scan_depth or config.get("scanDepth") or "light"
    scan_start_date = config.get("scanStartDate") or None
    update_secret_run(org, run_id, {"scanDepth": resolved_scan_depth})

    try:
        succeeded_sources: list[int] = []
        failure_msg = ""

        for source_idx, source in enumerate(repo_sources):
            if runtime and runtime.is_cancelled(run_id):
                return mark_run_cancelled(org, run_id)

            repo_urls_str = ",".join(source.repo_urls)

            result = _execute_via_runner(
                run_id=run_id,
                config=config,
                repo_urls=repo_urls_str,
                token=source.token,
                scan_depth=resolved_scan_depth,
                scan_start_date=scan_start_date,
            )

            if runtime and runtime.is_cancelled(run_id):
                return mark_run_cancelled(org, run_id)

            if not result or result.get("status") in ("failed", "cancelled"):
                failure_msg = result.get("error", "Runner job failed") if result else "Runner job timed out"
                logger.warning("Secret source scan failed: %s", failure_msg)
            else:
                succeeded_sources.append(source_idx)

        if not succeeded_sources:
            return _transition_run(
                org,
                run_id,
                "failed",
                {
                    "finishedAt": now_iso(),
                    "error": failure_msg or "All sources failed",
                },
            )

        # Final status set by ingest_secrets_from_minio on runner callback
        return read_secret_run(org, run_id)
    except Exception as error:
        if runtime and runtime.is_cancelled(run_id):
            return mark_run_cancelled(org, run_id)
        return _transition_run(
            org,
            run_id,
            "failed",
            {
                "finishedAt": now_iso(),
                "error": str(error),
                "lastHeartbeatAt": now_iso(),
                "progress": {
                    "expectedRepos": resolved_expected_repos,
                    "scannedRepos": 0,
                    "finishedRepos": 0,
                    "percent": 0,
                    "currentRepo": None,
                    "stage": "failed",
                },
            },
        )
    finally:
        if runtime and runtime_started:
            runtime.release(org)
