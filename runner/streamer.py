# runner/streamer.py
"""Stream file uploads to MinIO by polling _manifest.jsonl in a dedicated thread."""
from __future__ import annotations

import hashlib
import json
import logging
import re
import threading
import time
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Allow relative paths with safe characters — reject traversal (..),
# absolute paths (/), and special characters
_SAFE_RELATIVE_PATH = re.compile(r"^[a-zA-Z0-9._-]+(/[a-zA-Z0-9._-]+)*$")

POLL_INTERVAL = 3  # seconds between manifest polls
RETRY_WAIT = 5  # seconds before retrying failed files
MAX_FINISH_WAIT = 600  # max seconds to wait for uploads after scanner exits


def _sha256_chunked(file_path: Path) -> str:
    """Compute sha256 in chunks to avoid loading large files into memory."""
    h = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


class ManifestStreamer:
    """Upload files listed in _manifest.jsonl as they appear during a scan."""

    def __init__(
        self,
        job_dir: Path,
        upload_fn: Any,
        tool: str,
        org: str,
        run_id: str,
    ):
        self.job_dir = job_dir
        self.manifest_path = job_dir / "_manifest.jsonl"
        self.upload_fn: Any = upload_fn
        self.tool = tool
        self.org = org
        self.run_id = run_id
        self.last_line = 0
        self.scanner_done = False
        self.uploaded_count = 0
        self.failed_count = 0
        self._failed_entries: list[dict[str, Any]] = []
        self._uploaded_files: set[str] = set()

        self.done_event = threading.Event()      # caller sets when scanner exits
        self.finished_event = threading.Event()  # streamer sets when all uploads complete

    def run(self) -> None:
        """Poll manifest and upload files until scanner exits."""
        logger.info("[+] [streamer] Started for %s/%s/%s", self.tool, self.org, self.run_id)

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
            logger.exception("[!] [streamer] Unexpected error in streamer thread")
        finally:
            logger.info(
                "[✓] [streamer] Finished: %d uploaded, %d failed",
                self.uploaded_count, self.failed_count,
            )
            self.finished_event.set()

    def _poll(self) -> None:
        """Read new manifest entries, verify integrity, and upload."""
        if not self.manifest_path.exists():
            return

        try:
            lines = self.manifest_path.read_text().splitlines()
        except OSError:
            return

        new_lines = lines[self.last_line:]

        for line in new_lines:
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                break  # partial line — retry next poll

            filename = entry.get("file", "")

            if filename == "_done":
                self.scanner_done = True
                self.last_line += 1
                continue

            if not _SAFE_RELATIVE_PATH.match(filename):
                logger.warning("[!] [streamer] Rejected unsafe path: %s", filename)
                self.failed_count += 1
                self.last_line += 1
                continue

            file_path = self.job_dir / filename
            if not file_path.exists():
                break  # not yet written to disk

            expected_hash = entry.get("sha256", "")
            actual_hash = _sha256_chunked(file_path)
            if actual_hash != expected_hash:
                time.sleep(2)  # file may still be flushing to disk
                actual_hash = _sha256_chunked(file_path)
                if actual_hash != expected_hash:
                    logger.warning(
                        "[!] [streamer] sha256 mismatch for %s: expected=%s actual=%s",
                        filename, expected_hash, actual_hash,
                    )
                    self._failed_entries.append(entry)
                    self.failed_count += 1
                    self.last_line += 1
                    continue

            if self._upload_file(file_path, filename):
                self.uploaded_count += 1
            else:
                self._failed_entries.append(entry)
                self.failed_count += 1

            self.last_line += 1

    def _upload_file(self, file_path: Path, filename: str) -> bool:
        s3_key = f"{self.tool}/{self.org}/{self.run_id}/{filename}"
        ok = self.upload_fn(file_path, s3_key)
        if ok:
            self._uploaded_files.add(filename)
        return ok

    def _retry_failed(self) -> None:
        still_failed: list[dict[str, Any]] = []

        for entry in self._failed_entries:
            filename = entry.get("file", "")
            file_path = self.job_dir / filename

            if not file_path.exists():
                still_failed.append(entry)
                continue

            expected_hash = entry.get("sha256", "")
            actual_hash = _sha256_chunked(file_path)
            if actual_hash != expected_hash:
                logger.warning("[!] [streamer] Retry sha256 still mismatched: %s", filename)
                still_failed.append(entry)
                continue

            if self._upload_file(file_path, filename):
                logger.info("[✓] [streamer] Retry succeeded: %s", filename)
                self.uploaded_count += 1
                self.failed_count -= 1
            else:
                still_failed.append(entry)

        self._failed_entries = still_failed

    def _finalize(self) -> None:
        """Bulk-upload remaining files not covered by manifest streaming."""
        import concurrent.futures

        remaining = []
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

        # Ingestion-critical files first, then everything else
        CRITICAL = {"findings.json", "sbom.cdx.json"}
        critical = [(fp, rel) for fp, rel in remaining if fp.name in CRITICAL]
        non_critical = [(fp, rel) for fp, rel in remaining if fp.name not in CRITICAL]

        logger.info("[+] [streamer] Bulk-uploading %d files (%d critical, %d audit)",
                     len(remaining), len(critical), len(non_critical))

        bulk_count = 0
        bulk_failed = 0

        def _upload_one(item: tuple[Path, str]) -> bool:
            file_path, relative = item
            s3_key = f"{self.tool}/{self.org}/{self.run_id}/{relative}"
            return self.upload_fn(file_path, s3_key)

        if critical:
            with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
                results = pool.map(_upload_one, critical)
                for ok in results:
                    if ok:
                        bulk_count += 1
                    else:
                        bulk_failed += 1
            logger.info("[✓] [streamer] Critical files uploaded: %d/%d", bulk_count, len(critical))

        if non_critical:
            with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
                for i, ok in enumerate(pool.map(_upload_one, non_critical)):
                    if ok:
                        bulk_count += 1
                    else:
                        bulk_failed += 1
                    if (i + 1) % 100 == 0:
                        logger.info("[+] [streamer] Bulk upload progress: %d/%d", i + 1, len(non_critical))

        self.uploaded_count += bulk_count
        self.failed_count += bulk_failed
        logger.info("[✓] [streamer] Bulk-uploaded %d files (%d failed)", bulk_count, bulk_failed)

        if self.manifest_path.exists():
            s3_key = f"{self.tool}/{self.org}/{self.run_id}/_manifest.jsonl"
            self.upload_fn(self.manifest_path, s3_key)

    def get_progress(self) -> dict[str, Any]:
        """Thread-safe upload progress snapshot."""
        return {
            "filesUploaded": self.uploaded_count,
            "filesFailed": self.failed_count,
        }
