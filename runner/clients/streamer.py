"""Stream file uploads to MinIO via backend-minted presigned URLs."""
from __future__ import annotations

import concurrent.futures
import hashlib
import json
import logging
import re
import threading
import time
from pathlib import Path
from typing import Any, Callable

from runner.clients.backend import BackendClient, BackendError
from runner.clients.uploader import URL_EXPIRED_MARKER, post_to_url
from runner.observability.metrics import presign_url_expired_total

logger = logging.getLogger(__name__)

_SAFE_RELATIVE_PATH = re.compile(r"^_?[a-zA-Z0-9][a-zA-Z0-9._-]*(/[a-zA-Z0-9][a-zA-Z0-9._-]*)*$")

POLL_INTERVAL = 3
RETRY_WAIT = 5
MAX_FINISH_WAIT = 600


def _sha256_chunked(file_path: Path) -> str:
    h = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


PostFn = Callable[[Path, str, dict], str]


class ManifestStreamer:
    """Upload files listed in _manifest.jsonl as they appear during a scan."""

    def __init__(
        self,
        *,
        job_dir: Path,
        backend_client: BackendClient,
        job_id: str,
        post_fn: PostFn = post_to_url,
    ) -> None:
        self.job_dir = job_dir
        self.manifest_path = job_dir / "_manifest.jsonl"
        self.backend = backend_client
        self.job_id = job_id
        self.post_fn = post_fn

        self.last_line = 0
        self.scanner_done = False
        self.uploaded_count = 0
        self.failed_count = 0
        self._failed_entries: list[dict[str, Any]] = []
        self._uploaded_files: set[str] = set()

        self.done_event = threading.Event()
        self.finished_event = threading.Event()

    def run(self) -> None:
        logger.info("[+] [streamer] Started for job %s", self.job_id)
        try:
            while not self.done_event.is_set():
                self._poll()
                self.done_event.wait(timeout=POLL_INTERVAL)
            self._poll()
            if self._failed_entries:
                logger.info("[+] [streamer] Retrying %d failed uploads", len(self._failed_entries))
                time.sleep(RETRY_WAIT)
                self._retry_failed()
            self._finalize()
        except Exception:
            logger.exception("[!] [streamer] Unexpected error")
        finally:
            logger.info(
                "[✓] [streamer] Finished: %d uploaded, %d failed",
                self.uploaded_count, self.failed_count,
            )
            self.finished_event.set()

    def _poll(self) -> None:
        if not self.manifest_path.exists():
            return

        try:
            lines = self.manifest_path.read_text().splitlines()
        except OSError:
            return

        new_lines = lines[self.last_line:]
        batch: list[dict[str, Any]] = []
        consumed = 0

        for line in new_lines:
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                break

            consumed += 1
            filename = entry.get("file", "")

            if filename == "_done":
                self.scanner_done = True
                continue

            if not _SAFE_RELATIVE_PATH.match(filename):
                logger.warning("[!] [streamer] Rejected unsafe path: %s", filename)
                self.failed_count += 1
                continue

            file_path = self.job_dir / filename
            if not file_path.exists():
                consumed -= 1
                break

            expected = entry.get("sha256", "")
            actual = _sha256_chunked(file_path)
            if actual != expected:
                time.sleep(2)
                actual = _sha256_chunked(file_path)
                if actual != expected:
                    logger.warning("[!] [streamer] sha256 mismatch for %s", filename)
                    self._failed_entries.append(entry)
                    self.failed_count += 1
                    continue

            batch.append(entry)

        self.last_line += consumed
        if batch:
            self._upload_batch(batch)

    def _upload_batch(self, entries: list[dict[str, Any]]) -> None:
        files = [e["file"] for e in entries]
        try:
            urls = self.backend.presign_uploads(self.job_id, files)
        except BackendError as exc:
            if exc.status == 409:
                logger.info("[~] [streamer] job no longer running (409) — stopping")
                self.done_event.set()
                return
            logger.warning("[!] [streamer] presign failed (%s) — queueing for retry", exc)
            self._failed_entries.extend(entries)
            self.failed_count += len(entries)
            return

        for entry in entries:
            name = entry["file"]
            spec = urls.get(name)
            if not spec:
                logger.warning("[!] [streamer] backend did not return URL for %s", name)
                self._failed_entries.append(entry)
                self.failed_count += 1
                continue

            result = self.post_fn(self.job_dir / name, spec["url"], spec["fields"])
            if result == "ok":
                self.uploaded_count += 1
                self._uploaded_files.add(name)
            elif result == URL_EXPIRED_MARKER:
                presign_url_expired_total.inc()
                if self._retry_one_with_fresh_url(entry):
                    self.uploaded_count += 1
                    self._uploaded_files.add(name)
                else:
                    self._failed_entries.append(entry)
                    self.failed_count += 1
            else:
                self._failed_entries.append(entry)
                self.failed_count += 1

    def _retry_one_with_fresh_url(self, entry: dict[str, Any]) -> bool:
        name = entry["file"]
        try:
            urls = self.backend.presign_uploads(self.job_id, [name])
        except BackendError as exc:
            logger.warning("[!] [streamer] re-presign failed for %s: %s", name, exc)
            return False
        spec = urls.get(name)
        if not spec:
            return False
        return self.post_fn(self.job_dir / name, spec["url"], spec["fields"]) == "ok"

    def _retry_failed(self) -> None:
        still_failed: list[dict[str, Any]] = []
        candidates: list[dict[str, Any]] = []
        for entry in self._failed_entries:
            file_path = self.job_dir / entry["file"]
            if not file_path.exists():
                still_failed.append(entry)
                continue
            if _sha256_chunked(file_path) != entry.get("sha256", ""):
                still_failed.append(entry)
                continue
            candidates.append(entry)

        if not candidates:
            self._failed_entries = still_failed
            return

        try:
            urls = self.backend.presign_uploads(self.job_id, [e["file"] for e in candidates])
        except BackendError as exc:
            logger.warning("[!] [streamer] retry presign failed: %s", exc)
            still_failed.extend(candidates)
            self._failed_entries = still_failed
            return

        for entry in candidates:
            name = entry["file"]
            spec = urls.get(name)
            if not spec:
                still_failed.append(entry)
                continue
            result = self.post_fn(self.job_dir / name, spec["url"], spec["fields"])
            if result == "ok":
                self.uploaded_count += 1
                self.failed_count -= 1
                self._uploaded_files.add(name)
            else:
                still_failed.append(entry)

        self._failed_entries = still_failed

    def _finalize(self) -> None:
        remaining: list[tuple[Path, str]] = []
        for file_path in self.job_dir.rglob("*"):
            if not file_path.is_file():
                continue
            if file_path.name == "_manifest.jsonl":
                continue
            relative = str(file_path.relative_to(self.job_dir))
            if relative in self._uploaded_files:
                continue
            remaining.append((file_path, relative))

        if not remaining:
            return

        critical = {"findings.json", "sbom.cdx.json"}
        critical_items = [(p, r) for p, r in remaining if p.name in critical]
        rest = [(p, r) for p, r in remaining if p.name not in critical]

        logger.info(
            "[+] [streamer] Bulk-uploading %d files (%d critical)",
            len(remaining), len(critical_items),
        )
        if critical_items:
            self._bulk_put(critical_items)
        if rest:
            self._bulk_put(rest)

        if self.manifest_path.exists():
            try:
                urls = self.backend.presign_uploads(self.job_id, ["_manifest.jsonl"])
            except BackendError as exc:
                logger.warning("[!] [streamer] manifest presign failed: %s", exc)
                return
            spec = urls.get("_manifest.jsonl")
            if spec:
                self.post_fn(self.manifest_path, spec["url"], spec["fields"])

    def _bulk_put(self, items: list[tuple[Path, str]]) -> None:
        names = [rel for _, rel in items]
        try:
            urls = self.backend.presign_uploads(self.job_id, names)
        except BackendError as exc:
            logger.warning("[!] [streamer] bulk presign failed: %s", exc)
            self.failed_count += len(items)
            return

        def _one(item: tuple[Path, str]) -> bool:
            path, relative = item
            spec = urls.get(relative)
            if not spec:
                return False
            return self.post_fn(path, spec["url"], spec["fields"]) == "ok"

        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            for ok in pool.map(_one, items):
                if ok:
                    self.uploaded_count += 1
                else:
                    self.failed_count += 1

    def get_progress(self) -> dict[str, Any]:
        return {
            "filesUploaded": self.uploaded_count,
            "filesFailed": self.failed_count,
        }
