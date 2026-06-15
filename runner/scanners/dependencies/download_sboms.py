"""Download SBOMs for the dependencies advisories_only scan mode."""
from __future__ import annotations

import logging
from pathlib import Path

import httpx

from runner.clients.backend import BackendClient

logger = logging.getLogger(__name__)


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
        target = output_dir / name
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
