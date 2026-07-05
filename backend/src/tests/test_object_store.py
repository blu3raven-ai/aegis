"""Coverage for the object-store client's real logic (not boto passthrough).

The thin put/get wrappers are uninteresting, but the error handling
(missing-key → None, other errors re-raised), the corrupt-blob tolerance, the
pagination flattening, and the findings.jsonl selection priority are real
behaviour SBOM/findings retrieval depends on. Driven through a fake S3 client.
"""
from __future__ import annotations

import json

import pytest
from botocore.exceptions import ClientError

from src.shared import object_store


def _client_error(code: str):
    return ClientError({"Error": {"Code": code, "Message": "x"}}, "GetObject")


class _Body:
    def __init__(self, data: bytes):
        self._data = data

    def read(self, amt: int | None = None):
        # Mirror boto3 StreamingBody.read(amt): bounded read when amt is given.
        if amt is None:
            return self._data
        chunk, self._data = self._data[:amt], self._data[amt:]
        return chunk


class _FakeS3:
    """Configurable stand-in for the boto3 S3 client."""

    def __init__(self, *, objects=None, pages=None, tags=None, presigned="http://internal/x"):
        # objects: {key: bytes} for get_object; missing key raises NoSuchKey.
        self.objects = objects or {}
        self.pages = pages if pages is not None else []
        self.tags = tags
        self.presigned = presigned
        self.deleted: list[str] = []
        self.raise_on_get: ClientError | None = None
        self.raise_on_tags: ClientError | None = None
        self.post_conditions = None

    def get_object(self, *, Bucket, Key):
        if self.raise_on_get is not None:
            raise self.raise_on_get
        if Key not in self.objects:
            raise _client_error("NoSuchKey")
        return {"Body": _Body(self.objects[Key])}

    def get_paginator(self, _op):
        pages = self.pages

        class _Pag:
            def paginate(self, **_kw):
                return iter(pages)

        return _Pag()

    def delete_object(self, *, Bucket, Key):
        self.deleted.append(Key)

    def generate_presigned_url(self, *_a, **_kw):
        return self.presigned

    def generate_presigned_post(self, *, Bucket, Key, Conditions, ExpiresIn):
        self.post_conditions = Conditions
        return {"url": self.presigned, "fields": {"key": Key, "policy": "b64"}}

    def get_object_tagging(self, *, Bucket, Key):
        if self.raise_on_tags is not None:
            raise self.raise_on_tags
        return {"TagSet": self.tags or []}


@pytest.fixture
def fake(monkeypatch):
    client = _FakeS3()
    monkeypatch.setattr(object_store, "get_s3_client", lambda: client)
    return client


# ── download_bytes ───────────────────────────────────────────────────────────

def test_generate_upload_post_caps_size_in_policy(fake):
    out = object_store.generate_upload_post("scans/f.json", max_bytes=1024)
    assert out["fields"]  # policy/signature fields the runner POSTs with the file
    # The store enforces the cap at upload time via this condition.
    assert ["content-length-range", 0, 1024] in fake.post_conditions


def test_generate_upload_post_rewrites_external_host(fake, monkeypatch):
    monkeypatch.setattr(object_store, "_S3_ENDPOINT", "http://internal:9000")
    monkeypatch.setattr(object_store, "_S3_EXTERNAL_ENDPOINT", "https://public.example")
    fake.presigned = "http://internal:9000/scans"
    out = object_store.generate_upload_post("scans/f.json", max_bytes=10, external=True)
    assert out["url"] == "https://public.example/scans"


def test_download_bytes_returns_body(fake):
    fake.objects = {"k1": b"hello"}
    assert object_store.download_bytes("k1") == b"hello"


def test_download_bytes_rejects_oversized(fake, monkeypatch):
    # An oversized (e.g. malicious-runner) blob is refused, not read into memory.
    monkeypatch.setattr(object_store, "MAX_OBJECT_BYTES", 4)
    fake.objects = {"big": b"toolarge"}
    assert object_store.download_bytes("big") is None


def test_download_bytes_allows_at_cap(fake, monkeypatch):
    monkeypatch.setattr(object_store, "MAX_OBJECT_BYTES", 8)
    fake.objects = {"ok": b"exactly8"}
    assert object_store.download_bytes("ok") == b"exactly8"


@pytest.mark.parametrize("code", ["NoSuchKey", "404"])
def test_download_bytes_missing_key_returns_none(fake, code):
    fake.raise_on_get = _client_error(code)
    assert object_store.download_bytes("absent") is None


def test_download_bytes_other_error_reraises(fake):
    fake.raise_on_get = _client_error("AccessDenied")
    with pytest.raises(ClientError):
        object_store.download_bytes("k1")


# ── download_json ────────────────────────────────────────────────────────────

def test_download_json_parses_valid(fake):
    fake.objects = {"k": json.dumps({"a": 1}).encode()}
    assert object_store.download_json("k") == {"a": 1}


def test_download_json_missing_returns_none(fake):
    fake.raise_on_get = _client_error("NoSuchKey")
    assert object_store.download_json("k") is None


def test_download_json_corrupt_blob_returns_none(fake):
    fake.objects = {"k": b"{not valid json"}
    # Corrupt/truncated blob is treated as missing, not a 500.
    assert object_store.download_json("k") is None


# ── list_objects / delete_prefix ─────────────────────────────────────────────

def test_list_objects_flattens_pages(fake):
    fake.pages = [
        {"Contents": [{"Key": "p/a"}, {"Key": "p/b"}]},
        {"Contents": [{"Key": "p/c"}]},
        {},  # empty page (no Contents) must not crash
    ]
    assert object_store.list_objects("p/") == ["p/a", "p/b", "p/c"]


def test_delete_prefix_deletes_each_and_counts(fake):
    fake.pages = [{"Contents": [{"Key": "p/a"}, {"Key": "p/b"}]}]
    assert object_store.delete_prefix("p/") == 2
    assert fake.deleted == ["p/a", "p/b"]


def test_delete_prefix_empty_returns_zero(fake):
    fake.pages = [{}]
    assert object_store.delete_prefix("p/") == 0
    assert fake.deleted == []


# ── find_findings_jsonl ──────────────────────────────────────────────────────

def test_find_findings_prefers_exact_name(fake):
    fake.objects = {"run/findings.jsonl": b"EXACT"}
    assert object_store.find_findings_jsonl("run/") == b"EXACT"


def test_find_findings_falls_back_to_other_jsonl_skipping_manifest(fake):
    # No exact findings.jsonl; a _manifest.jsonl must be skipped in favour of a
    # real results file.
    fake.objects = {"run/results_manifest.jsonl": b"MANIFEST", "run/dep.jsonl": b"REAL"}
    fake.pages = [{"Contents": [{"Key": "run/results_manifest.jsonl"}, {"Key": "run/dep.jsonl"}]}]
    assert object_store.find_findings_jsonl("run/") == b"REAL"


def test_find_findings_returns_none_when_absent(fake):
    fake.pages = [{"Contents": [{"Key": "run/other.txt"}]}]
    assert object_store.find_findings_jsonl("run/") is None


# ── presign external rewrite + tags ──────────────────────────────────────────

def test_generate_upload_url_rewrites_to_external(fake, monkeypatch):
    monkeypatch.setattr(object_store, "_S3_ENDPOINT", "http://internal")
    monkeypatch.setattr(object_store, "_S3_EXTERNAL_ENDPOINT", "https://public")
    fake.presigned = "http://internal/scans/key?sig=abc"
    out = object_store.generate_upload_url("key", external=True)
    assert out == "https://public/scans/key?sig=abc"


def test_generate_upload_url_no_rewrite_when_internal(fake, monkeypatch):
    monkeypatch.setattr(object_store, "_S3_ENDPOINT", "http://internal")
    monkeypatch.setattr(object_store, "_S3_EXTERNAL_ENDPOINT", "https://public")
    fake.presigned = "http://internal/scans/key?sig=abc"
    assert object_store.generate_upload_url("key", external=False) == "http://internal/scans/key?sig=abc"


def test_get_object_tags_maps_tagset(fake):
    fake.tags = [{"Key": "env", "Value": "prod"}, {"Key": "team", "Value": "core"}]
    assert object_store.get_object_tags("k") == {"env": "prod", "team": "core"}


def test_get_object_tags_swallows_error_to_empty(fake):
    fake.raise_on_tags = _client_error("NoSuchKey")
    assert object_store.get_object_tags("k") == {}
