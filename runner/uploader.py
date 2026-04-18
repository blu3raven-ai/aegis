# runner/uploader.py
"""Upload scanner output files to MinIO with retry."""
from __future__ import annotations

import logging
import os
import time
from pathlib import Path

import boto3
from botocore.config import Config

logger = logging.getLogger(__name__)

S3_ENDPOINT = os.environ.get("S3_ENDPOINT", "http://minio:9000")
S3_ACCESS_KEY = os.environ.get("S3_ACCESS_KEY", "")
S3_SECRET_KEY = os.environ.get("S3_SECRET_KEY", "")
S3_BUCKET = os.environ.get("S3_BUCKET", "scans")
S3_REGION = os.environ.get("S3_REGION", "us-east-1")

MAX_RETRIES = 3
RETRY_BACKOFF = [2, 5, 10]  # seconds between retries

_client = None


def _get_client():
    global _client
    if _client is None:
        _client = boto3.client(
            "s3",
            endpoint_url=S3_ENDPOINT,
            aws_access_key_id=S3_ACCESS_KEY,
            aws_secret_access_key=S3_SECRET_KEY,
            region_name=S3_REGION,
            config=Config(
                signature_version="s3v4",
                connect_timeout=10,
                read_timeout=120,
                retries={"max_attempts": 0},
            ),
        )
    return _client


def _upload_file_with_retry(client, bucket: str, key: str, data: bytes, content_type: str) -> bool:
    for attempt in range(MAX_RETRIES):
        try:
            client.put_object(Bucket=bucket, Key=key, Body=data, ContentType=content_type)
            return True
        except Exception as exc:
            if attempt < MAX_RETRIES - 1:
                wait = RETRY_BACKOFF[attempt]
                logger.warning("[!] Upload attempt %d failed for %s: %s. Retrying in %ds...", attempt + 1, key, exc, wait)
                time.sleep(wait)
            else:
                logger.error("[!] Upload failed after %d attempts for %s: %s", MAX_RETRIES, key, exc)
                return False
    return False


def upload_file(file_path: Path, s3_key: str) -> bool:
    """Upload a single file to MinIO. Returns True on success."""
    client = _get_client()

    ext = file_path.suffix
    content_type = {
        ".json": "application/json",
        ".jsonl": "application/x-ndjson",
        ".txt": "text/plain",
    }.get(ext, "application/octet-stream")

    data = file_path.read_bytes()
    return _upload_file_with_retry(client, S3_BUCKET, s3_key, data, content_type)


