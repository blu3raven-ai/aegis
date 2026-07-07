"""Download SBOMs for the dependencies advisories_only scan mode."""
from __future__ import annotations

import logging
from pathlib import Path, PurePosixPath

import httpx

from runner.clients.backend import BackendClient

logger = logging.getLogger(__name__)


def _is_safe_relative_path(name: str) -> bool:
    """Return True only when name is safe to join onto an output directory.

    Rejects null bytes (which can truncate filenames on some platforms),
    absolute paths, and any component equal to '..' so a malicious server
    cannot escape the output directory before Path.resolve() is even called.
    """
    if not name or '\x00' in name:
        return False
    p = PurePosixPath(name)
    return not p.is_absolute() and '..' not in p.parts


def download_sboms(
    *,
    backend_client: BackendClient,
    job_id: str,
    output_dir: Path,
) -> int:
    """Fetch the SBOM list for this job and write each one to disk.

    Returns the count of files written."""
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    entries = backend_client.list_sbom_downloads(job_id)
    written = 0
    for entry in entries:
        name = entry["file"]
        url = entry["url"]
        # Reject names with null bytes, absolute paths, or '..' traversal before
        # any path construction so a malicious server can't sneak past the check.
        if not _is_safe_relative_path(name):
            logger.warning("[!] SBOM download skipped unsafe path: %s", name)
            continue
        # Secondary guard: resolve the joined path and confirm it stays inside
        # output_dir (catches symlink-based traversal the name check cannot see).
        target = (output_dir / name).resolve()
        if not str(target).startswith(str(output_dir.resolve())):
            logger.warning("[!] SBOM download skipped unsafe path: %s", name)
            continue
        try:
            with httpx.Client(timeout=60.0) as client:
                resp = client.get(url)
            if 200 <= resp.status_code < 300:
                target.write_bytes(resp.content)
                written += 1
            else:
                logger.warning("[!] SBOM download failed %s: HTTP %d", name, resp.status_code)
        except httpx.RequestError as exc:
            logger.warning("[!] SBOM download network error for %s: %s", name, exc)
    return written
