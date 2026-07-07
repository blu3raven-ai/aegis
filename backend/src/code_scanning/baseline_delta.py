"""Cache-aware SAST scan engine.

Phase 2c ships the engine logic and cache integration. Live Opengrep subprocess
wiring is deferred — callers inject opengrep_runner so tests can mock without
subprocesses and production can swap in real runners later.

Merge formula for a delta scan:
    new_baseline = (cached_findings_for_unchanged_files)
                 ∪ (new_findings_from_changed_files)
                 − (findings_for_deleted_files)

A full scan is triggered when:
  - baseline_sha is None (first scan for this repo), or
  - rule_pack_version differs from the version that produced the cached findings
    (new rules must be applied to all files, not just changed ones).
"""
from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from src.code_scanning.diff_detector import compute_file_diff
from src.code_scanning.file_finding_cache import FileFindingCache, Finding


@dataclass
class SastScanResult:
    findings: list[Finding]
    cached_files: int       # files whose results came from cache
    rescanned_files: int    # files Opengrep was actually called on
    deleted_files: int      # files whose cached findings were invalidated
    duration_ms: int


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    h.update(path.read_bytes())
    return h.hexdigest()


class SastBaselineDelta:
    """Incremental SAST scanner: reuses per-file cached findings when content unchanged."""

    def __init__(
        self,
        cache: FileFindingCache,
        opengrep_runner: Callable[[Path, list[str]], list[Finding]],
    ) -> None:
        self._cache = cache
        self._runner = opengrep_runner

    def scan(
        self,
        *,
        repo_id: str,
        checkout_path: Path,
        baseline_sha: str | None,
        head_sha: str,
        rule_pack_version: str,
    ) -> SastScanResult:
        """Run a cache-aware SAST scan.

        Full scan path (baseline_sha is None OR rule_pack_version changed):
          - Run Opengrep on every file; cache per-file results.

        Delta scan path (baseline known and rule pack unchanged):
          - Compute diff; scan only added+modified files.
          - Load cached findings for unchanged files.
          - Invalidate deleted files.
        """
        t0 = time.monotonic()
        diff = compute_file_diff(checkout_path, baseline_sha, head_sha)

        # Determine whether a full scan is required.
        # baseline_sha=None means the diff returns all files as 'added',
        # which naturally triggers a full scan via the same code path.
        # A rule pack version change requires rescanning unchanged files too.
        rule_pack_changed = self._rule_pack_changed(repo_id, rule_pack_version)
        force_full = baseline_sha is None or rule_pack_changed

        if force_full:
            return self._full_scan(
                repo_id=repo_id,
                checkout_path=checkout_path,
                all_files=diff.added,  # baseline_sha=None → all files are 'added'
                rule_pack_version=rule_pack_version,
                t0=t0,
            )

        return self._delta_scan(
            repo_id=repo_id,
            checkout_path=checkout_path,
            diff=diff,
            rule_pack_version=rule_pack_version,
            t0=t0,
        )

    # ── internal scan paths ───────────────────────────────────────────────────

    def _full_scan(
        self,
        *,
        repo_id: str,
        checkout_path: Path,
        all_files: list[str],
        rule_pack_version: str,
        t0: float,
    ) -> SastScanResult:
        all_findings: list[Finding] = []

        for rel_path in all_files:
            abs_path = checkout_path / rel_path
            if not abs_path.is_file():
                continue
            file_sha = _sha256_file(abs_path)
            file_findings = self._runner(abs_path, [rel_path])
            self._cache.put(repo_id, rel_path, file_sha, file_findings, rule_pack_version)
            all_findings.extend(file_findings)

        return SastScanResult(
            findings=all_findings,
            cached_files=0,
            rescanned_files=len(all_files),
            deleted_files=0,
            duration_ms=int((time.monotonic() - t0) * 1000),
        )

    def _delta_scan(
        self,
        *,
        repo_id: str,
        checkout_path: Path,
        diff,
        rule_pack_version: str,
        t0: float,
    ) -> SastScanResult:
        all_findings: list[Finding] = []
        cached_files = 0
        rescanned_files = 0

        # Rescan added + modified files; update cache
        for rel_path in diff.added + diff.modified:
            abs_path = checkout_path / rel_path
            if not abs_path.is_file():
                continue
            file_sha = _sha256_file(abs_path)

            cached = self._cache.get(repo_id, rel_path, file_sha, rule_pack_version)
            if cached is not None:
                all_findings.extend(cached)
                cached_files += 1
            else:
                file_findings = self._runner(abs_path, [rel_path])
                self._cache.put(repo_id, rel_path, file_sha, file_findings, rule_pack_version)
                all_findings.extend(file_findings)
                rescanned_files += 1

        # Load cached findings for files that weren't touched in this diff
        # (not in added, modified, or deleted)
        touched = set(diff.added + diff.modified + diff.deleted)
        for entry in self._cache.list_repo_entries(repo_id):
            # cache_key format: '{repo_id}|{file_path}|{sha256}'
            parts = entry.cache_key.split("|", 2)
            if len(parts) != 3:
                continue
            _, file_path, file_sha = parts
            if file_path in touched:
                continue
            # Validate rule pack version still matches
            if entry.rule_pack_version != rule_pack_version:
                continue
            abs_path = checkout_path / file_path
            if not abs_path.is_file():
                continue
            # Verify the on-disk sha matches the cached sha before trusting it
            if _sha256_file(abs_path) != file_sha:
                continue
            cached = self._cache.get(repo_id, file_path, file_sha, rule_pack_version)
            if cached is not None:
                all_findings.extend(cached)
                cached_files += 1

        # Invalidate deleted files
        deleted_count = 0
        for rel_path in diff.deleted:
            removed = self._cache.invalidate_file(repo_id, rel_path)
            deleted_count += removed

        return SastScanResult(
            findings=all_findings,
            cached_files=cached_files,
            rescanned_files=rescanned_files,
            deleted_files=deleted_count,
            duration_ms=int((time.monotonic() - t0) * 1000),
        )

    def _rule_pack_changed(self, repo_id: str, rule_pack_version: str) -> bool:
        """Return True if any cached entry for this repo has a different rule pack version.

        If the repo has no cache entries yet, this is a first scan — handled
        separately by baseline_sha=None.
        """
        entries = self._cache.list_repo_entries(repo_id)
        if not entries:
            return False
        # If any entry has a different rule pack, we need a full rescan
        return any(e.rule_pack_version != rule_pack_version for e in entries)
