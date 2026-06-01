"""Download a previously stored container SBOM from MinIO.

Port of the inline ``minio`` block in scanners/container/run.sh's
``scan_advisories_only`` function. Uses boto3 (the runner's standard S3
client) instead of the ``minio`` lib used in bash — the wire protocol is the
same and boto3 is already a hard dependency of this image.

Storage layout (must match the dependencies-scanner uploader output):
    bucket = $S3_BUCKET (defaults to "sboms")
    key    = "<org_label>/<sanitized_image_ref>/sbom.cdx.json"
where ``sanitized_image_ref`` is the image ref with ``[/:]`` replaced by
``_`` (mirrors the bash ``sed 's/[/:]/_/g'``).
"""
from __future__ import annotations

import logging
import os
import re
from pathlib import Path

logger = logging.getLogger(__name__)


_DEFAULT_SBOM_BUCKET = "sboms"
_SBOM_OBJECT_NAME = "sbom.cdx.json"
_S3_KEY_SANITIZE = re.compile(r"[/:]")


class SbomDownloadError(RuntimeError):
    """Raised when the SBOM cannot be retrieved for an image."""


def _s3_key_for(image_ref: str) -> str:
    """Return the sanitized image-ref segment used in the object key.

    Mirrors the bash ``echo "$image_ref" | sed 's/[/:]/_/g'`` — only ``/``
    and ``:`` are remapped, all other characters are preserved (the bash
    validation gate already enforces the safe charset upstream)."""
    return _S3_KEY_SANITIZE.sub("_", image_ref)


def download_sbom_for_image(
    image_ref: str,
    output_path: Path,
    *,
    s3_client=None,
) -> Path:
    """Download a stored SBOM for ``image_ref`` into ``output_path``.

    Reads ``S3_ENDPOINT``, ``S3_ACCESS_KEY``, ``S3_SECRET_KEY``,
    ``S3_REGION``, ``S3_BUCKET`` and ``ORG_LABEL`` from the environment.
    Raises ``SbomDownloadError`` with a descriptive message on any failure —
    fail-loud is required by the calling scanner to mark the image as
    unscannable rather than silently producing empty findings.
    """
    org = os.environ.get("ORG_LABEL")
    if not org:
        raise SbomDownloadError("ORG_LABEL not set; cannot resolve SBOM key")

    endpoint = os.environ.get("S3_ENDPOINT")
    access_key = os.environ.get("S3_ACCESS_KEY")
    secret_key = os.environ.get("S3_SECRET_KEY")
    if not endpoint:
        raise SbomDownloadError("S3_ENDPOINT not set")
    if not access_key or not secret_key:
        raise SbomDownloadError("S3 credentials not set")

    bucket = os.environ.get("S3_BUCKET") or _DEFAULT_SBOM_BUCKET
    region = os.environ.get("S3_REGION") or "us-east-1"

    client = s3_client
    if client is None:
        import boto3
        from botocore.config import Config

        client = boto3.client(
            "s3",
            endpoint_url=endpoint,
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            region_name=region,
            config=Config(signature_version="s3v4"),
        )

    key = f"{org}/{_s3_key_for(image_ref)}/{_SBOM_OBJECT_NAME}"
    output_path.parent.mkdir(parents=True, exist_ok=True)

    try:
        client.download_file(bucket, key, str(output_path))
    except Exception as e:  # noqa: BLE001 — boto3 raises a wide tree
        raise SbomDownloadError(
            f"Failed to download SBOM s3://{bucket}/{key}: {e}"
        ) from e

    if not output_path.exists() or output_path.stat().st_size == 0:
        raise SbomDownloadError(
            f"Downloaded SBOM s3://{bucket}/{key} is empty"
        )
    return output_path


__all__ = ("download_sbom_for_image", "SbomDownloadError")
