"""Shared checkout → MinIO tarball uploader for scanner adapters.

The secrets, code-scanning, and dependencies adapters each had a near-byte-
identical ``_upload_checkout_to_minio`` helper. Centralising it here keeps the
adapters focused on their wire contracts and pins the canonical object-key
layout (``<bucket>/<scanner>/<uuid>.tar.gz``) in a single place.

Object key layout
-----------------
``aegis-checkouts/<scanner>/<uuid>.tar.gz`` — the ``<scanner>`` segment lets
operators filter MinIO objects by source; the UUID dodges collisions when
multiple scans run concurrently against the same repo. The earlier
``<scan_id>/<repo>.tar.gz`` derivation from ``checkout_path.parts[-2:]`` was
brittle (depended on caller convention) and is dropped in this refactor.
"""
from __future__ import annotations

import io
import logging
import os
import tarfile
import uuid
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

_MINIO_BUCKET = "aegis-checkouts"


# ─── Typed exceptions ───────────────────────────────────────────────────────
# Subclasses of RuntimeError so callers that catch RuntimeError still work,
# but adapters that want to discriminate (e.g. translate missing creds into
# AdapterUnavailableError vs operational failures into AdapterFailedError)
# can do so without string-matching on the message.


class CheckoutUploadError(RuntimeError):
    """Base for upload helper errors."""


class MinioCredentialsMissing(CheckoutUploadError):
    """S3 endpoint or credentials env vars are unset."""


class MinioOperationFailed(CheckoutUploadError):
    """Network / API / bucket failure during upload."""


# ─── Pooled boto3 client (avoids TLS handshake per upload) ──────────────────


_s3_client: Any = None


def _get_s3_client() -> Any:
    """Return a process-wide singleton boto3 S3 client.

    Lazy so importing this module does not require S3 credentials. The first
    call validates env vars and constructs the client; subsequent calls return
    the cached instance.

    Raises
    ------
    MinioCredentialsMissing
        If any of ``S3_ENDPOINT`` / ``S3_ACCESS_KEY`` / ``S3_SECRET_KEY`` is
        unset. The exception message names the env vars so the operator does
        not have to spelunk for them.
    """
    global _s3_client
    if _s3_client is not None:
        return _s3_client

    endpoint = os.environ.get("S3_ENDPOINT", "").strip()
    access_key = os.environ.get("S3_ACCESS_KEY", "").strip()
    secret_key = os.environ.get("S3_SECRET_KEY", "").strip()
    if not endpoint or not access_key or not secret_key:
        raise MinioCredentialsMissing(
            "MinIO checkout transport requires S3_ENDPOINT/S3_ACCESS_KEY/S3_SECRET_KEY"
        )

    import boto3

    _s3_client = boto3.client(
        "s3",
        endpoint_url=endpoint,
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
    )
    return _s3_client


def _reset_s3_client_for_tests() -> None:
    """Clear the cached client. Tests-only; production code never calls this."""
    global _s3_client
    _s3_client = None


# ─── Public API ─────────────────────────────────────────────────────────────


def _ensure_bucket(client: Any) -> None:
    """Idempotent bucket-create — mirrors the pattern in sbom_storage /
    object_store so a fresh MinIO deployment does not need out-of-band
    provisioning. Safe to call on every upload; head_bucket is cheap.
    """
    try:
        client.head_bucket(Bucket=_MINIO_BUCKET)
    except Exception:
        try:
            client.create_bucket(Bucket=_MINIO_BUCKET)
        except Exception as exc:
            raise MinioOperationFailed(
                f"cannot ensure checkouts bucket: {exc}"
            ) from exc


def upload_checkout(scanner: str, checkout_path: Path) -> str:
    """Tar ``checkout_path`` and PUT it into MinIO. Return the ``bucket/key`` ref.

    Parameters
    ----------
    scanner:
        Source scanner name — surfaces as the first key segment so operators
        can grep object listings per scanner. Free-form string but should be
        a stable identifier (``secrets``, ``sast``, ``dependencies``).
    checkout_path:
        Directory to tarball. The arcname is fixed to ``checkout`` so the
        scanner-side extractor sees a consistent layout regardless of where
        the backend stored the working copy locally.

    Returns
    -------
    ``aegis-checkouts/<scanner>/<uuid>.tar.gz`` — fully-qualified bucket/key
    reference matching the regex the scanner http_api validates against.

    Raises
    ------
    MinioCredentialsMissing
        Propagated from :func:`_get_s3_client` when the S3 env vars are unset.
    MinioOperationFailed
        On any network / API / bucket failure during the upload itself.
    """
    client = _get_s3_client()
    _ensure_bucket(client)

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        tf.add(str(checkout_path), arcname="checkout")
    buf.seek(0)

    object_key = f"{scanner}/{uuid.uuid4().hex}.tar.gz"
    try:
        client.put_object(
            Bucket=_MINIO_BUCKET,
            Key=object_key,
            Body=buf.getvalue(),
            ContentType="application/gzip",
        )
    except Exception as exc:
        raise MinioOperationFailed(
            f"put_object failed for {_MINIO_BUCKET}/{object_key}: {exc}"
        ) from exc
    return f"{_MINIO_BUCKET}/{object_key}"
