"""S3-compatible object store client."""
from __future__ import annotations

import json
import logging
import os
from typing import Any

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)

_S3_ENDPOINT = os.environ.get("S3_ENDPOINT", "http://localhost:9000")
_S3_EXTERNAL_ENDPOINT = os.environ.get("S3_EXTERNAL_ENDPOINT", "")
_S3_ACCESS_KEY = os.environ.get("S3_ACCESS_KEY", "")
_S3_SECRET_KEY = os.environ.get("S3_SECRET_KEY", "")
_S3_BUCKET = os.environ.get("S3_BUCKET", "scans")
_S3_REGION = os.environ.get("S3_REGION", "us-east-1")

_client = None


def get_s3_client():
    global _client
    if _client is None:
        _client = boto3.client(
            "s3",
            endpoint_url=_S3_ENDPOINT,
            aws_access_key_id=_S3_ACCESS_KEY,
            aws_secret_access_key=_S3_SECRET_KEY,
            region_name=_S3_REGION,
            config=Config(signature_version="s3v4"),
        )
        ensure_bucket()
    return _client


def ensure_bucket() -> None:
    client = _client or boto3.client(
        "s3",
        endpoint_url=_S3_ENDPOINT,
        aws_access_key_id=_S3_ACCESS_KEY,
        aws_secret_access_key=_S3_SECRET_KEY,
        region_name=_S3_REGION,
        config=Config(signature_version="s3v4"),
    )
    try:
        client.head_bucket(Bucket=_S3_BUCKET)
    except ClientError:
        client.create_bucket(Bucket=_S3_BUCKET)
        logger.info("Created S3 bucket: %s", _S3_BUCKET)


def generate_upload_url(key: str, expires_in: int = 300, external: bool = False) -> str:
    """Generate a pre-signed PUT URL. If external=True, rewrites to S3_EXTERNAL_ENDPOINT."""
    url = get_s3_client().generate_presigned_url(
        "put_object",
        Params={"Bucket": _S3_BUCKET, "Key": key},
        ExpiresIn=expires_in,
    )
    if external and _S3_EXTERNAL_ENDPOINT and _S3_ENDPOINT:
        url = url.replace(_S3_ENDPOINT, _S3_EXTERNAL_ENDPOINT, 1)
    return url


def generate_upload_post(
    key: str,
    *,
    max_bytes: int,
    expires_in: int = 300,
    external: bool = False,
) -> dict:
    """Generate a pre-signed POST whose policy caps the upload size.

    A pre-signed PUT URL cannot bound the request body, so a client can upload an
    arbitrarily large object and exhaust storage before ingest ever reads it. The
    POST policy carries a ``content-length-range`` condition, so the object store
    rejects an oversized upload at upload time. Returns ``{"url", "fields"}``; the
    caller POSTs a multipart form of ``fields`` plus the file. ``external`` rewrites
    the URL host to ``S3_EXTERNAL_ENDPOINT`` for off-cluster runners.
    """
    post = get_s3_client().generate_presigned_post(
        Bucket=_S3_BUCKET,
        Key=key,
        Conditions=[["content-length-range", 0, max_bytes]],
        ExpiresIn=expires_in,
    )
    if external and _S3_EXTERNAL_ENDPOINT and _S3_ENDPOINT:
        post["url"] = post["url"].replace(_S3_ENDPOINT, _S3_EXTERNAL_ENDPOINT, 1)
    return post


def generate_download_url(key: str, expires_in: int = 300, bucket: str = _S3_BUCKET) -> str:
    """Generate a pre-signed GET URL."""
    return get_s3_client().generate_presigned_url(
        "get_object",
        Params={"Bucket": bucket, "Key": key},
        ExpiresIn=expires_in,
    )


def upload_bytes(key: str, data: bytes, content_type: str = "application/octet-stream", bucket: str = _S3_BUCKET) -> None:
    get_s3_client().put_object(
        Bucket=bucket,
        Key=key,
        Body=data,
        ContentType=content_type,
    )


# Cap in-memory object reads so an oversized (e.g. runner-supplied) blob can't
# OOM the ingest worker. read(N+1) bounds the read regardless of a possibly
# understated ContentLength.
MAX_OBJECT_BYTES = 512 * 1024 * 1024


def download_bytes(key: str, bucket: str = _S3_BUCKET) -> bytes | None:
    try:
        response = get_s3_client().get_object(Bucket=bucket, Key=key)
        data = response["Body"].read(MAX_OBJECT_BYTES + 1)
        if len(data) > MAX_OBJECT_BYTES:
            logger.warning(
                "Object %s exceeds the %d-byte cap — refusing to load", key, MAX_OBJECT_BYTES
            )
            return None
        return data
    except ClientError as e:
        if e.response["Error"]["Code"] in ("NoSuchKey", "404"):
            return None
        raise


def download_json(key: str) -> dict[str, Any] | None:
    data = download_bytes(key)
    if not data:
        return None
    try:
        return json.loads(data)
    except (json.JSONDecodeError, ValueError):
        # A truncated/corrupt blob (e.g. an interrupted upload) is treated as
        # unreadable rather than crashing the caller with a 500.
        logger.warning("Unparseable JSON blob at %s — treating as missing", key)
        return None


def delete_prefix(prefix: str, bucket: str = _S3_BUCKET) -> int:
    client = get_s3_client()
    objects = list_objects(prefix, bucket=bucket)
    if not objects:
        return 0
    for key in objects:
        client.delete_object(Bucket=bucket, Key=key)
    return len(objects)


def list_objects(prefix: str, bucket: str = _S3_BUCKET) -> list[str]:
    client = get_s3_client()
    keys: list[str] = []
    paginator = client.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket, Prefix=prefix):
        for obj in page.get("Contents", []):
            keys.append(obj["Key"])
    return keys


def find_findings_jsonl(prefix: str) -> bytes | None:
    """Download findings.jsonl from a prefix, falling back to any .jsonl file.

    Returns bytes (possibly empty b"") if found, None if no file exists.
    """
    data = download_bytes(f"{prefix}findings.jsonl")
    if data is not None:
        return data

    for key in list_objects(prefix):
        if key.endswith(".jsonl") and "_manifest" not in key:
            data = download_bytes(key)
            if data is not None:
                return data
    return None


def tag_object(key: str, tags: dict[str, str]) -> None:
    tag_set = [{"Key": k, "Value": v} for k, v in tags.items()]
    get_s3_client().put_object_tagging(
        Bucket=_S3_BUCKET,
        Key=key,
        Tagging={"TagSet": tag_set},
    )


def get_object_tags(key: str) -> dict[str, str]:
    try:
        response = get_s3_client().get_object_tagging(Bucket=_S3_BUCKET, Key=key)
        return {t["Key"]: t["Value"] for t in response.get("TagSet", [])}
    except ClientError:
        return {}
