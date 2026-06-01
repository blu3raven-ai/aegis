"""Tests for ``src.shared.checkout_upload``.

The three scanner adapters (secrets, sast, dependencies) now share this
helper. Failures here ripple through every minio-transport scanner so the
coverage is intentionally exhaustive on auth and key-layout invariants.
"""
from __future__ import annotations

import io
import sys
import tarfile
from pathlib import Path
from unittest.mock import MagicMock

import pytest


# ─── _get_s3_client lazy singleton ──────────────────────────────────────────


def test_get_s3_client_is_cached_singleton(monkeypatch):
    from src.shared import checkout_upload

    monkeypatch.setenv("S3_ENDPOINT", "http://minio:9000")
    monkeypatch.setenv("S3_ACCESS_KEY", "k")
    monkeypatch.setenv("S3_SECRET_KEY", "s")
    checkout_upload._reset_s3_client_for_tests()

    boto3_calls: list = []

    def fake_boto3_client(*args, **kwargs):
        boto3_calls.append((args, kwargs))
        return MagicMock()

    fake_boto3 = MagicMock()
    fake_boto3.client = fake_boto3_client
    monkeypatch.setitem(sys.modules, "boto3", fake_boto3)

    c1 = checkout_upload._get_s3_client()
    c2 = checkout_upload._get_s3_client()

    assert c1 is c2
    assert len(boto3_calls) == 1


def test_get_s3_client_raises_when_credentials_missing(monkeypatch):
    from src.shared import checkout_upload
    from src.shared.checkout_upload import MinioCredentialsMissing

    monkeypatch.delenv("S3_ENDPOINT", raising=False)
    monkeypatch.delenv("S3_ACCESS_KEY", raising=False)
    monkeypatch.delenv("S3_SECRET_KEY", raising=False)
    checkout_upload._reset_s3_client_for_tests()

    with pytest.raises(
        MinioCredentialsMissing, match="S3_ENDPOINT/S3_ACCESS_KEY/S3_SECRET_KEY"
    ):
        checkout_upload._get_s3_client()
    # Subclass-of-RuntimeError invariant — existing callers still catch.
    assert issubclass(MinioCredentialsMissing, RuntimeError)


# ─── upload_checkout ────────────────────────────────────────────────────────


def test_upload_checkout_returns_canonical_key(monkeypatch, tmp_path):
    """Key layout must match the regex the scanner http_api validates:
    ``aegis-checkouts/<scanner>/<uuid>.tar.gz``.
    """
    from src.shared import checkout_upload

    checkout = tmp_path / "scan-x" / "repo-y"
    checkout.mkdir(parents=True)
    (checkout / "package.json").write_text("{}")

    fake_client = MagicMock()
    monkeypatch.setattr(checkout_upload, "_get_s3_client", lambda: fake_client)

    key = checkout_upload.upload_checkout("secrets", checkout)

    assert key.startswith("aegis-checkouts/secrets/")
    assert key.endswith(".tar.gz")
    # uuid hex segment is 32 chars
    suffix = key[len("aegis-checkouts/secrets/"):-len(".tar.gz")]
    assert len(suffix) == 32
    assert all(c in "0123456789abcdef" for c in suffix)


def test_upload_checkout_puts_tarball_with_checkout_arcname(monkeypatch, tmp_path):
    """The tarball arcname is fixed to ``checkout`` so the scanner-side
    extractor sees a stable layout regardless of the local working copy path.
    """
    from src.shared import checkout_upload

    checkout = tmp_path / "anything"
    checkout.mkdir()
    (checkout / "Cargo.toml").write_text('name = "x"')

    captured: dict = {}

    fake_client = MagicMock()

    def fake_put_object(**kwargs):
        captured.update(kwargs)
        return {}

    fake_client.put_object.side_effect = fake_put_object
    monkeypatch.setattr(checkout_upload, "_get_s3_client", lambda: fake_client)

    checkout_upload.upload_checkout("sast", checkout)

    assert captured["Bucket"] == "aegis-checkouts"
    assert captured["ContentType"] == "application/gzip"

    tar_body = captured["Body"]
    with tarfile.open(fileobj=io.BytesIO(tar_body), mode="r:gz") as tf:
        names = tf.getnames()
    # arcname is "checkout" so every entry must be rooted under it
    assert all(n == "checkout" or n.startswith("checkout/") for n in names)
    assert "checkout/Cargo.toml" in names


def test_upload_checkout_keys_collision_resistant(monkeypatch, tmp_path):
    """Two uploads of the same checkout must yield distinct object keys —
    the UUID dodges the collision the brittle parts[-2:] convention had.
    """
    from src.shared import checkout_upload

    checkout = tmp_path / "scan-1" / "repo-a"
    checkout.mkdir(parents=True)
    (checkout / "file.txt").write_text("x")

    fake_client = MagicMock()
    monkeypatch.setattr(checkout_upload, "_get_s3_client", lambda: fake_client)

    k1 = checkout_upload.upload_checkout("dependencies", checkout)
    k2 = checkout_upload.upload_checkout("dependencies", checkout)

    assert k1 != k2


def test_upload_checkout_propagates_missing_credentials(monkeypatch, tmp_path):
    from src.shared import checkout_upload
    from src.shared.checkout_upload import MinioCredentialsMissing

    monkeypatch.delenv("S3_ENDPOINT", raising=False)
    monkeypatch.delenv("S3_ACCESS_KEY", raising=False)
    monkeypatch.delenv("S3_SECRET_KEY", raising=False)
    checkout_upload._reset_s3_client_for_tests()

    checkout = tmp_path / "x"
    checkout.mkdir()

    with pytest.raises(MinioCredentialsMissing, match="S3_"):
        checkout_upload.upload_checkout("secrets", checkout)


def test_upload_checkout_bucket_ensure_failure_raises_operation_failed(
    monkeypatch, tmp_path
):
    """If head_bucket fails and create_bucket also fails (e.g. MinIO down or
    permissions denied), the caller must see MinioOperationFailed — not the
    raw boto3 exception and not a generic RuntimeError.
    """
    from src.shared import checkout_upload
    from src.shared.checkout_upload import MinioOperationFailed

    checkout = tmp_path / "scan"
    checkout.mkdir()

    fake_client = MagicMock()
    fake_client.head_bucket.side_effect = Exception("NoSuchBucket")
    fake_client.create_bucket.side_effect = Exception("AccessDenied")
    monkeypatch.setattr(checkout_upload, "_get_s3_client", lambda: fake_client)

    with pytest.raises(MinioOperationFailed, match="cannot ensure checkouts bucket"):
        checkout_upload.upload_checkout("secrets", checkout)


def test_upload_checkout_put_object_failure_raises_operation_failed(
    monkeypatch, tmp_path
):
    """A network blip on put_object must surface as MinioOperationFailed so
    adapters can map it to AdapterFailedError instead of misclassifying it
    as a transient unavailable.
    """
    from src.shared import checkout_upload
    from src.shared.checkout_upload import MinioOperationFailed

    checkout = tmp_path / "scan"
    checkout.mkdir()

    fake_client = MagicMock()
    fake_client.head_bucket.return_value = {}
    fake_client.put_object.side_effect = Exception("connection reset by peer")
    monkeypatch.setattr(checkout_upload, "_get_s3_client", lambda: fake_client)

    with pytest.raises(MinioOperationFailed, match="put_object failed"):
        checkout_upload.upload_checkout("dependencies", checkout)


def test_upload_checkout_creates_bucket_on_fresh_deployment(monkeypatch, tmp_path):
    """A fresh MinIO instance has no aegis-checkouts bucket — the helper must
    create it rather than fail the first scan.
    """
    from src.shared import checkout_upload

    checkout = tmp_path / "scan"
    checkout.mkdir()

    fake_client = MagicMock()
    fake_client.head_bucket.side_effect = Exception("NoSuchBucket")
    monkeypatch.setattr(checkout_upload, "_get_s3_client", lambda: fake_client)

    checkout_upload.upload_checkout("dependencies", checkout)

    fake_client.create_bucket.assert_called_once_with(Bucket="aegis-checkouts")
    fake_client.put_object.assert_called_once()
