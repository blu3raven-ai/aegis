"""Download a previously stored container SBOM via the backend presign API.

For ``advisories_only`` mode the runner needs the SBOM that the prior full
scan uploaded for each image. It now fetches the listing through the
backend (presigned GET URLs) instead of talking to MinIO directly with S3
credentials.

Storage layout (must match ``backend.containers.sbom_store._sbom_s3_key``):
    bucket = sboms
    key    = "<org>/<sanitized_image_ref>/sbom.cdx.json"
where ``sanitized_image_ref = image_ref.replace('/', '_').replace(':', '_')``.

The backend's ``list_job_sboms`` endpoint returns ``[{"file", "url"}, ...]``
with ``file`` set to ``key[len("sboms/<org>/"):]`` after replacing ``/`` with
``__``. So an image stored at ``sboms/acme/gcr.io_proj_img_1.0/sbom.cdx.json``
arrives as ``gcr.io_proj_img_1.0__sbom.cdx.json``.
"""
from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any

import httpx

logger = logging.getLogger(__name__)


_SBOM_OBJECT_NAME = "sbom.cdx.json"
_S3_KEY_SANITIZE = re.compile(r"[/:]")


class SbomDownloadError(RuntimeError):
    """Raised when the SBOM cannot be retrieved for an image."""


def _sanitized_image_segment(image_ref: str) -> str:
    """Return the sanitized image-ref segment used in the object key.

    Mirrors ``backend.containers.sbom_store._sbom_s3_key`` — only ``/`` and
    ``:`` are remapped, all other characters are preserved."""
    return _S3_KEY_SANITIZE.sub("_", image_ref)


def _expected_listing_filename(image_ref: str) -> str:
    """Filename the backend listing returns for this image's SBOM."""
    return f"{_sanitized_image_segment(image_ref)}__{_SBOM_OBJECT_NAME}"


def download_sbom_for_image(
    image_ref: str,
    output_path: Path,
    *,
    backend_client: Any,
    job_id: str,
) -> Path:
    """Download the stored SBOM for ``image_ref`` into ``output_path``.

    Raises ``SbomDownloadError`` with a descriptive message on any failure —
    fail-loud is required by the calling scanner to mark the image as
    unscannable rather than silently producing empty findings.
    """
    expected = _expected_listing_filename(image_ref)
    try:
        entries = backend_client.list_sbom_downloads(job_id)
    except Exception as exc:
        raise SbomDownloadError(
            f"Failed to list SBOMs for job {job_id}: {exc}"
        ) from exc

    match = next((e for e in entries if e.get("file") == expected), None)
    if not match:
        raise SbomDownloadError(
            f"No stored SBOM listing entry for {image_ref} (expected {expected})"
        )

    url = match.get("url")
    if not url:
        raise SbomDownloadError(
            f"SBOM listing entry for {image_ref} is missing a presigned url"
        )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with httpx.Client(timeout=60.0) as client:
            resp = client.get(url)
    except httpx.RequestError as exc:
        raise SbomDownloadError(
            f"Network error downloading SBOM for {image_ref}: {exc}"
        ) from exc

    if not (200 <= resp.status_code < 300):
        raise SbomDownloadError(
            f"SBOM download for {image_ref} returned HTTP {resp.status_code}"
        )

    output_path.write_bytes(resp.content)
    if not output_path.exists() or output_path.stat().st_size == 0:
        raise SbomDownloadError(
            f"Downloaded SBOM for {image_ref} is empty"
        )
    return output_path


__all__ = ("download_sbom_for_image", "SbomDownloadError")
