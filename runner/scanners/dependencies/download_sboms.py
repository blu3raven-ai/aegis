"""Download SBOMs from MinIO for advisories_only mode.

Port of scanners/dependencies/scripts/download-sboms.py. Imports boto3 lazily
so the rest of the dependencies scanner remains usable without the optional
S3 client dependency."""
from __future__ import annotations

import logging
import os
from pathlib import Path

logger = logging.getLogger(__name__)


class SbomDownloadError(RuntimeError):
    """Raised when SBOM download cannot proceed (missing config, etc.)."""


def download_sboms(output_dir: Path | str = "/scanner/input/sboms") -> int:
    """Download every <org>/<repo>/sbom.json from the 'sboms' bucket.

    Reads ORG_LABEL, S3_ENDPOINT, S3_ACCESS_KEY, S3_SECRET_KEY, S3_REGION
    from the environment. Returns the count of downloaded SBOMs."""
    org = os.environ.get("ORG_LABEL", "")
    if not org:
        raise SbomDownloadError("ORG_LABEL not set")

    import boto3
    from botocore.config import Config

    client = boto3.client(
        "s3",
        endpoint_url=os.environ["S3_ENDPOINT"],
        aws_access_key_id=os.environ["S3_ACCESS_KEY"],
        aws_secret_access_key=os.environ["S3_SECRET_KEY"],
        region_name=os.environ.get("S3_REGION", "us-east-1"),
        config=Config(signature_version="s3v4"),
    )

    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    prefix = f"{org}/"
    paginator = client.get_paginator("list_objects_v2")
    count = 0

    for page in paginator.paginate(Bucket="sboms", Prefix=prefix):
        for obj in page.get("Contents", []):
            key = obj["Key"]
            if key.endswith("/sbom.json"):
                repo = (
                    key.replace(prefix, "")
                    .replace("/sbom.json", "")
                    .replace("/", "__")
                )
                path = out / f"{repo}.json"
                client.download_file("sboms", key, str(path))
                count += 1

    logger.info("[+] Downloaded %d SBOMs from MinIO", count)
    return count
