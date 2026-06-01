"""Cache-aware secrets scan engine.

Phase 2d ships the engine logic and verification cache integration. Live
TruffleHog subprocess wiring is deferred — callers inject trufflehog_runner
so tests can mock without subprocesses.

Key correctness property: unlike SAST (file-level) and SBOM (manifest-level)
caches, secrets are checked per-commit. A secret committed at any point in
history is still leaked even if the file was later deleted. The push path
therefore scans NEW COMMITS (not file diffs), while periodic sweeps re-scan
full history.

Verification cost reduction:
  verified_secrets_cache.get(detector_id, secret_hash)
    hit + not expired  → reuse status, record as "skipped-cache-hit"
    miss or expired    → call live verifier, cache result

Detector version change invalidates cached entries by prefixing detector_id
with the version string: "trufflehog@3.82.1::AWS". This guarantees a version
bump forces re-verification without an explicit cache flush step.
"""
from __future__ import annotations

import hashlib
import json
import logging
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from src.secrets.commit_range import CommitInfo, enumerate_new_commits
from src.secrets.verified_secrets_cache import VerifiedSecretsCache

logger = logging.getLogger(__name__)


@dataclass
class SecretFinding:
    commit_sha: str
    file_path: str
    line: int
    detector_id: str
    secret_hash: str
    verified: bool
    verification_status: str   # "verified" | "unverified" | "skipped-cache-hit" | "revoked" | "unreachable"


@dataclass
class SecretsScanResult:
    findings: list[SecretFinding]
    commits_scanned: int
    cached_verifications: int   # verifications skipped due to cache hit
    new_verifications: int      # verifications actually called
    duration_ms: int


def _hash_secret(raw_value: str) -> str:
    """SHA-256 of the secret content — stored instead of the plaintext."""
    return hashlib.sha256(raw_value.encode()).hexdigest()


def _versioned_detector_id(detector_id: str, detector_version: str) -> str:
    """Prefix detector_id with version so a version bump busts all cached entries."""
    return f"{detector_version}::{detector_id}"


def _verify_with_trufflehog(detector_id: str, secret_value: str) -> str:
    """Verify a single candidate secret by running trufflehog against a temp file.

    Writes the secret value to a short-lived temp file, then runs:

        trufflehog filesystem file://<tmpfile> --json --no-update --only-verified

    Returns "verified" when trufflehog reports the secret as live, "unverified"
    otherwise. Returns "unverified" (not an error) when trufflehog is absent —
    surfacing findings without false negatives is the safe fallback.

    The temp file is always removed, even on error, so the secret value is not
    left on disk.
    """
    if shutil.which("trufflehog") is None:
        logger.debug("trufflehog not found on PATH; skipping live verification for %s", detector_id)
        return "unverified"

    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tmp:
        tmp.write(secret_value)
        tmp_path = tmp.name

    try:
        result = subprocess.run(
            [
                "trufflehog", "filesystem",
                f"file://{tmp_path}",
                "--json",
                "--no-update",
                "--only-verified",
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )
        # trufflehog exit 0 = clean, exit 183 = findings found; anything else is an error
        if result.returncode not in (0, 183):
            logger.warning(
                "trufflehog verification exited %d for detector %s; treating as unverified",
                result.returncode,
                detector_id,
            )
            return "unverified"

        # Any NDJSON lines in stdout mean trufflehog found verified secrets
        for line in result.stdout.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                finding = json.loads(line)
            except json.JSONDecodeError:
                continue
            if finding.get("Verified"):
                return "verified"

        return "unverified"
    except subprocess.TimeoutExpired:
        logger.warning("trufflehog verification timed out for detector %s", detector_id)
        return "unverified"
    except Exception:
        logger.exception("trufflehog verification failed unexpectedly for detector %s", detector_id)
        return "unverified"
    finally:
        try:
            Path(tmp_path).unlink(missing_ok=True)
        except Exception:
            pass


class SecretsBaselineDelta:
    """Incremental secrets scanner: reuses cached verification results within TTL."""

    def __init__(
        self,
        cache: VerifiedSecretsCache,
        trufflehog_runner: Callable[[Path, str], list[dict]],
    ) -> None:
        # trufflehog_runner(checkout_path, commit_sha) → list of candidate dicts
        # each dict: {detector_id, secret_value, file_path, line}
        self._cache = cache
        self._runner = trufflehog_runner

    def scan(
        self,
        *,
        repo_id: str,
        checkout_path: Path,
        baseline_sha: str | None,
        head_sha: str,
        detector_version: str,
    ) -> SecretsScanResult:
        """Run a cache-aware secrets scan over new commits.

        1. Enumerate new commits via commit_range.enumerate_new_commits.
        2. For each commit: call trufflehog_runner; for each candidate:
           - Hash secret content
           - Check cache; use cached status if valid
           - Call live verifier on miss; cache result
        3. Return merged result.
        """
        t0 = time.monotonic()
        commits = enumerate_new_commits(checkout_path, baseline_sha, head_sha)

        all_findings: list[SecretFinding] = []
        cached_verifications = 0
        new_verifications = 0

        for commit in commits:
            candidates = self._runner(checkout_path, commit.sha)
            for candidate in candidates:
                raw_detector_id = candidate["detector_id"]
                secret_value = candidate["secret_value"]
                file_path = candidate.get("file_path", "")
                line = candidate.get("line", 0)

                secret_hash = _hash_secret(secret_value)
                versioned_id = _versioned_detector_id(raw_detector_id, detector_version)

                cached = self._cache.get(versioned_id, secret_hash)
                if cached is not None:
                    # Cache hit within TTL — skip live verification
                    finding = SecretFinding(
                        commit_sha=commit.sha,
                        file_path=file_path,
                        line=line,
                        detector_id=raw_detector_id,
                        secret_hash=secret_hash,
                        verified=cached.status == "verified",
                        verification_status="skipped-cache-hit",
                    )
                    cached_verifications += 1
                else:
                    # Cache miss — call live verifier and cache result
                    status = _verify_with_trufflehog(raw_detector_id, secret_value)
                    self._cache.put(versioned_id, secret_hash, status=status)
                    finding = SecretFinding(
                        commit_sha=commit.sha,
                        file_path=file_path,
                        line=line,
                        detector_id=raw_detector_id,
                        secret_hash=secret_hash,
                        verified=status == "verified",
                        verification_status=status,
                    )
                    new_verifications += 1

                all_findings.append(finding)

        return SecretsScanResult(
            findings=all_findings,
            commits_scanned=len(commits),
            cached_verifications=cached_verifications,
            new_verifications=new_verifications,
            duration_ms=int((time.monotonic() - t0) * 1000),
        )
