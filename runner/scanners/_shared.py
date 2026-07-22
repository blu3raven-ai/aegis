"""Port of scanners/shared/lib.sh — helpers shared by every scanner module.

Stdout progress markers MUST match the exact strings emitted by the bash
originals so the runner's ManifestStreamer regex parser continues to work."""
from __future__ import annotations

import concurrent.futures
import dataclasses
import json
import logging
import os
import re
import subprocess
import threading
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlsplit, urlunsplit

from runner.scanners import _manifest
from runner.scanners._manifest import write_done_marker
from runner.scanners._subprocess import CANCELLED_EXIT_CODE, ScannerTimeoutError
from runner.scanners.base import ExecutionResult

logger = logging.getLogger(__name__)


class InsecureURLError(ValueError):
    """Raised when a non-HTTPS git URL is passed to clone_repo."""


class GitCloneError(RuntimeError):
    """Raised when git clone fails. Token is scrubbed from any captured output."""


# A conservative id charset: no '/', no leading '.', so '..', absolute paths, and
# path separators can never survive into a workspace path built from an id.
_SAFE_ID_RE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")


def require_safe_id(value: str, *, kind: str = "id") -> str:
    """Reject any id that could traverse out of the workspace when joined into a
    path. jobId/runId arrive from the backend job payload; a forged one like
    ``../../home/aegis/.vuln-runner`` must not reach a filesystem path."""
    if not isinstance(value, str) or not _SAFE_ID_RE.match(value):
        raise ValueError(f"Unsafe {kind}: {value!r}")
    return value


def setup_output_dir(job_id: str, base_dir: Path | str = "/workspace") -> Path:
    """Create and return /<base_dir>/<job_id>/. Idempotent."""
    require_safe_id(job_id, kind="job_id")
    out = Path(base_dir) / job_id
    out.mkdir(parents=True, exist_ok=True)
    return out


def repo_name_from_url(url: str) -> str:
    """Extract the repository basename from a git URL.

    Strips .git suffix and trailing slashes, validates the resulting name
    is a safe single path component, then sanitizes remaining characters.
    Raises ValueError for names that would be unsafe as filesystem path components.
    """
    import re as _re
    path = url.rstrip("/")
    if path.endswith(".git"):
        path = path[:-4]
    path = path.rstrip("/")
    raw = path.rsplit("/", 1)[-1]
    # Use Path.name to strip any embedded separators (e.g. backslashes).
    name = Path(raw).name
    if not name or name in (".", "..") or "/" in name or "\x00" in name:
        raise ValueError(f"Unsafe repository name derived from URL: {url!r}")
    # Sanitize: collapse non-word chars to underscores.
    name = _re.sub(r"[^\w\-]", "_", name).strip("_") or "repo"
    return name


def derive_html_url(repo_url: str) -> str:
    """Derive a repo's web URL from its clone URL.

    Strips any embedded ``user:pass@`` credentials (only for ``https://`` URLs)
    and a trailing ``.git`` suffix, so the result is safe to expose and links to
    the browsable repo. Host-agnostic: works for cloud and self-hosted SCM hosts.
    """
    url = repo_url
    if url.startswith("https://") and "@" in url[len("https://"):].split("/", 1)[0]:
        scheme, rest = url.split("://", 1)
        host_path = rest.split("@", 1)[1]
        url = f"{scheme}://{host_path}"
    if url.endswith(".git"):
        url = url[:-4]
    return url


def parse_repos(input_str: str) -> list[str]:
    """Accept comma- or newline-separated repos, or a path to a file with one per line."""
    if not input_str:
        return []
    looks_like_path = (
        len(input_str) < 4096
        and "\n" not in input_str
        and "," not in input_str
    )
    if looks_like_path:
        try:
            candidate = Path(input_str)
            raw = candidate.read_text() if candidate.is_file() else input_str
        except (OSError, ValueError):
            raw = input_str
    else:
        raw = input_str
    return [line.strip() for line in raw.replace(",", "\n").splitlines() if line.strip()]


def clone_repo(
    url: str,
    dest: Path | str,
    *,
    token: str | None = None,
    depth: int | None = 1,
    timeout: float = 300.0,
) -> None:
    """Clone a git repo. HTTPS-only; injects token via URL rewrite if provided.

    ``depth=None`` performs a full-history clone (no ``--depth`` / no
    ``--single-branch``) — required by the secrets scanner's ``deep`` mode
    which must walk every commit.
    """
    if not url.startswith("https://"):
        raise InsecureURLError(f"Refused non-HTTPS git URL: {url}")

    parts = urlsplit(url)
    if "@" in parts.netloc:
        raise InsecureURLError(f"Refused git URL containing embedded user-info: {url}")

    if token:
        netloc_with_auth = f"x-access-token:{token}@{parts.netloc}"
        auth_url = urlunsplit(
            (parts.scheme, netloc_with_auth, parts.path, parts.query, parts.fragment)
        )
    else:
        auth_url = url

    cmd = ["git", "clone"]
    if depth is not None:
        cmd.extend(["--depth", str(depth), "--single-branch"])
    cmd.extend([auth_url, str(dest)])
    try:
        subprocess.run(cmd, check=True, timeout=timeout, capture_output=True, text=True)
    except subprocess.CalledProcessError as e:
        stderr_clean = (e.stderr or "")
        if token:
            stderr_clean = stderr_clean.replace(auth_url, url)
        raise GitCloneError(
            f"git clone failed for {url}: rc={e.returncode}: {stderr_clean.strip()[:500]}"
        ) from None
    except subprocess.TimeoutExpired:
        raise GitCloneError(f"git clone timed out for {url} after {timeout}s") from None


def register_output(output_dir: Path, file_path: Path, repo: str) -> None:
    """Append a sha256 manifest entry for a per-repo output file."""
    _manifest.record_output(output_dir, file_path, repo)


def write_findings_jsonl(path: Path, findings: list[dict]) -> None:
    """Serialise findings to JSONL atomically (temp write + replace) so a reader
    or a concurrent streaming flush never observes a half-written file."""
    tmp = path.with_name(path.name + ".tmp")
    with open(tmp, "w") as f:
        for finding in findings:
            f.write(json.dumps(finding, separators=(",", ":")) + "\n")
    os.replace(tmp, path)


def log(prefix: str, target: str) -> None:
    """Emit a per-target progress marker to stdout (e.g. ``[scanning] acme/repo``)."""
    print(f"[{prefix}] {target}", flush=True)


class ProgressEmitter:
    """Thread-safe wrapper around the agent's ``on_progress`` callback.

    Tracks monotonic counters (scanned, finished) and emits the dict shape the
    backend expects. Safe to call from multiple threads (ThreadPoolExecutor).

    The agent merges its own streamer counters into the dict server-side, so
    this emitter intentionally does not track uploaded/failed counts.
    """

    def __init__(
        self,
        on_progress: Callable[[list[str], dict], None] | None,
        expected: int,
    ) -> None:
        self._on_progress = on_progress
        self._lock = threading.Lock()
        self._scanned = 0
        self._finished = 0
        self._expected = max(0, int(expected))
        self._stage = "starting"
        self._current_repo: str | None = None
        self._verifying_findings = 0

    def starting(self) -> None:
        with self._lock:
            self._stage = "starting"
            self._emit_locked()

    def scanning(self, repo: str) -> None:
        with self._lock:
            self._scanned += 1
            self._current_repo = repo
            self._stage = "scanning"
            self._emit_locked()

    def finished(self, repo: str) -> None:
        with self._lock:
            self._finished += 1
            if self._current_repo == repo:
                self._current_repo = None
            self._emit_locked()

    def detonating(self, repo: str) -> None:
        with self._lock:
            self._current_repo = repo
            self._stage = "detonating"
            self._emit_locked()

    def normalizing(self) -> None:
        with self._lock:
            self._stage = "normalizing"
            self._current_repo = None
            self._emit_locked()

    def verifying(self, findings_count: int) -> None:
        # LLM verification is the slow, unpredictable phase — generation time
        # varies per finding and there is no smooth percent to report. Surface
        # the count so the UI can show an honest indeterminate state instead
        # of a bar frozen at the pre-verify percentage.
        with self._lock:
            self._stage = "verifying"
            self._current_repo = None
            self._verifying_findings = max(0, int(findings_count))
            self._emit_locked()

    def done(self) -> None:
        with self._lock:
            self._finished = self._expected
            self._stage = "done"
            self._current_repo = None
            self._emit_locked()

    def _emit_locked(self) -> None:
        if self._on_progress is None:
            return
        progress: dict = {
            "scannedRepos": self._scanned,
            "finishedRepos": self._finished,
            "expectedRepos": self._expected,
            "stage": self._stage,
        }
        if self._current_repo:
            progress["currentRepo"] = self._current_repo
        if self._stage == "verifying" and getattr(self, "_verifying_findings", 0):
            progress["verifyingFindings"] = self._verifying_findings
        try:
            self._on_progress([], progress)
        except Exception:  # noqa: BLE001
            # A failed progress emission must never abort the scan.
            logger.debug("on_progress callback raised; ignoring", exc_info=True)


def run_per_repo(
    *,
    items: list[str],
    out_dir: Path,
    emitter: ProgressEmitter,
    concurrency: int,
    cancel_event: threading.Event | None,
    log_tail: list[str],
    scan_one: Callable[[str], object],
    label_of: Callable[[str], str] = repo_name_from_url,
    item_noun: str = "Repo",
    empty_message: str = "[!] No GIT_REPOS specified - nothing to scan",
    pre_scan: Callable[[], None] | None = None,
    post_scan: Callable[[], None] | None = None,
) -> ExecutionResult:
    """Shared clone→scan→register→emit skeleton for the per-item scanners.

    Runs ``scan_one(item)`` for each item across a ThreadPoolExecutor, wrapping
    every call with progress emission and uniform clone/timeout error handling,
    then writes the ``_done`` marker. ``pre_scan`` runs once after
    ``emitter.starting()`` and before the pool (e.g. one-time setup whose cost
    should be skipped on a cancelled or empty run); ``post_scan`` runs after the
    pool drains and before the marker (the normalize/verify hook). The
    cancel/empty guards short-circuit with the same exit codes each scanner used
    inline.
    """
    if cancel_event is not None and cancel_event.is_set():
        emitter.done()
        write_done_marker(out_dir)
        return ExecutionResult(
            exit_code=CANCELLED_EXIT_CODE, job_dir=out_dir, log_tail=log_tail
        )

    if not items:
        log_tail.append(empty_message)
        emitter.done()
        write_done_marker(out_dir)
        return ExecutionResult(exit_code=0, job_dir=out_dir, log_tail=log_tail)

    emitter.starting()

    if pre_scan is not None:
        pre_scan()

    def _run_one(item: str) -> None:
        if cancel_event is not None and cancel_event.is_set():
            return
        label = label_of(item)
        emitter.scanning(label)
        try:
            scan_one(item)
        except InsecureURLError as e:
            log_tail.append(f"[!] {e}")
        except GitCloneError as e:
            log_tail.append(f"[!] {e}")
        except ScannerTimeoutError as e:
            log_tail.append(f"[!] Timeout scanning {item}: {e}")
        except Exception as e:  # noqa: BLE001
            log_tail.append(f"[!] {item_noun} {item} failed: {e}")
            logger.exception("[!] %s %s failed", item_noun, item)
        finally:
            emitter.finished(label)

    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as pool:
        list(pool.map(_run_one, items))

    emitter.normalizing()
    if post_scan is not None:
        post_scan()
    write_done_marker(out_dir)
    emitter.done()

    exit_code = (
        CANCELLED_EXIT_CODE
        if (cancel_event is not None and cancel_event.is_set())
        else 0
    )
    return ExecutionResult(
        exit_code=exit_code, job_dir=out_dir, log_tail=log_tail[-50:]
    )


# ---------------------------------------------------------------------------
# Timeout constants (centralised from per-scanner modules)
# ---------------------------------------------------------------------------

TIMEOUT_CLONE: float = 300.0
TIMEOUT_GIT_QUERY: float = 30.0
TIMEOUT_SYFT_REPO: float = 600.0    # syft on git repo checkouts
TIMEOUT_SYFT_IMAGE: float = 900.0   # syft on container images (larger)
TIMEOUT_CDXGEN: float = 600.0
TIMEOUT_TRUFFLEHOG: float = 900.0
TIMEOUT_OPENGREP: float = 1800.0


# ---------------------------------------------------------------------------
# Exception hierarchy
# ---------------------------------------------------------------------------

class ScannerError(Exception):
    """Base for all scanner-level errors."""


class ScannerConfigError(ScannerError):
    """Job config is invalid — unsupported scan mode/depth, missing required env vars, etc."""


class ToolError(ScannerError):
    """An external tool (syft, grype, trufflehog, semgrep) exited with an error."""


# ---------------------------------------------------------------------------
# JobEnv — typed env-var reader
# ---------------------------------------------------------------------------

class JobEnv:
    """Reads env vars from job payload, falling back to os.environ."""

    def __init__(self, job: dict[str, Any]) -> None:
        self._vars: dict[str, str] = job.get("envVars") or {}

    def get(self, key: str, default: str = "") -> str:
        return self._vars.get(key) or os.environ.get(key) or default

    def get_int(self, key: str, default: int) -> int:
        raw = self.get(key)
        try:
            return int(raw) if raw else default
        except ValueError:
            return default


def build_llm_client(env: JobEnv):
    """Construct an LLM client from job env, or None when no BYO key is configured.

    The backend ships ``LLM_API_KEY`` (and friends) inside ``job['envVars']``,
    not the runner process environment, so ``JobEnv.get`` is the only correct
    read path.
    """
    from runner.verification.llm_client import LlmClient

    api_key = env.get("LLM_API_KEY")
    if not api_key:
        return None
    return LlmClient(
        api_key=api_key,
        api_base_url=env.get("LLM_API_BASE_URL", "https://api.openai.com/v1"),
        model=env.get("LLM_API_MODEL", "gpt-4o-mini"),
        # Generation on slow/self-hosted endpoints can exceed the 60s httpx
        # default — the agent judge's large prompt regularly did, which surfaced
        # as ReadTimeout and left agent findings unverified. Generous default;
        # chat() also retries on timeout. Overridable per job.
        timeout=float(env.get("LLM_TIMEOUT", "300")),
        # Default low: verification is bounded, so a reasoning model does not
        # need deep thinking, and low keeps its token spend from starving the
        # scan budget. Set LLM_REASONING_EFFORT to medium/high, or off to disable.
        reasoning_effort=env.get("LLM_REASONING_EFFORT") or "low",
    )


def build_escalation_llm_client(env: JobEnv):
    """Optional frontier escalation client — ``None`` unless ``LLM_ESCALATION_MODEL``
    is configured, so the tier is dormant by default.

    Defaults to the same key/endpoint as the primary client (a stronger model on
    the same provider), but ``LLM_ESCALATION_{API_KEY,BASE_URL}`` can point it at a
    different provider (e.g. a local small default + a hosted frontier tier).
    """
    from runner.verification.llm_client import LlmClient

    model = env.get("LLM_ESCALATION_MODEL")
    api_key = env.get("LLM_ESCALATION_API_KEY") or env.get("LLM_API_KEY")
    if not model or not api_key:
        return None
    return LlmClient(
        api_key=api_key,
        api_base_url=(
            env.get("LLM_ESCALATION_BASE_URL")
            or env.get("LLM_API_BASE_URL", "https://api.openai.com/v1")
        ),
        model=model,
        timeout=float(env.get("LLM_TIMEOUT", "300")),
        reasoning_effort=(
            env.get("LLM_ESCALATION_REASONING_EFFORT")
            or env.get("LLM_REASONING_EFFORT")
            or "low"
        ),
    )


# ---------------------------------------------------------------------------
# Base config dataclass
# ---------------------------------------------------------------------------

@dataclasses.dataclass(frozen=True)
class BaseScanConfig:
    org_label: str
    run_id: str
    concurrency: int


_COMMIT_SHA_RE = re.compile(r"\A[0-9a-fA-F]{7,64}\Z")


def compute_diff_files(repo_root: str, base_sha: str, head_sha: str) -> list[str]:
    """Return relative paths of files changed between ``base_sha`` and ``head_sha``.

    Both refs must be hex commit shas — they are interpolated into the ``git``
    argv, so a value that could begin with ``-`` would otherwise be parsed as an
    option rather than a revision. Raises ``ValueError`` if either ref is not a
    hex sha, if either commit is missing from the local clone, or if git itself
    errors. A 30s timeout guards against pathological histories.
    """
    if not _COMMIT_SHA_RE.match(base_sha) or not _COMMIT_SHA_RE.match(head_sha):
        raise ValueError("compute_diff_files requires hex commit shas")
    try:
        out = subprocess.run(
            ["git", "-C", repo_root, "diff", "--name-only", f"{base_sha}..{head_sha}", "--"],
            capture_output=True, text=True, check=True, timeout=30,
        )
    except subprocess.CalledProcessError as e:
        raise ValueError(f"git diff failed: {e.stderr[:200]}") from e
    except subprocess.TimeoutExpired as e:
        raise ValueError("git diff timed out") from e

    return [line.strip() for line in out.stdout.splitlines() if line.strip()]
