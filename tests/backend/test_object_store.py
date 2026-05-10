"""Tests for S3 object store client. Requires MinIO running locally."""
import json
import os
import pytest
from unittest.mock import patch, MagicMock

from src.shared.object_store import (
    get_s3_client,
    ensure_bucket,
    generate_upload_url,
    generate_download_url,
    upload_bytes,
    download_bytes,
    download_json,
    delete_prefix,
    list_objects,
    tag_object,
    get_object_tags,
)


def test_generate_upload_url_returns_string():
    url = generate_upload_url("test/key.json", expires_in=60)
    assert isinstance(url, str)
    assert "test/key.json" in url or "test%2Fkey.json" in url


def test_generate_download_url_returns_string():
    url = generate_download_url("test/key.json", expires_in=60)
    assert isinstance(url, str)


def test_upload_and_download_roundtrip():
    key = "test/roundtrip/data.json"
    data = b'{"hello": "world"}'
    upload_bytes(key, data, content_type="application/json")
    result = download_bytes(key)
    assert result == data
    # Cleanup
    delete_prefix("test/roundtrip/")


def test_download_json():
    key = "test/json/payload.json"
    payload = {"findings": [{"id": 1}]}
    upload_bytes(key, json.dumps(payload).encode(), content_type="application/json")
    result = download_json(key)
    assert result == payload
    delete_prefix("test/json/")


def test_delete_prefix_removes_all():
    upload_bytes("test/del/a.txt", b"a")
    upload_bytes("test/del/b.txt", b"b")
    upload_bytes("test/del/sub/c.txt", b"c")
    count = delete_prefix("test/del/")
    assert count >= 3
    remaining = list_objects("test/del/")
    assert len(remaining) == 0


def test_list_objects():
    upload_bytes("test/list/x.json", b"{}")
    upload_bytes("test/list/y.json", b"{}")
    keys = list_objects("test/list/")
    assert len(keys) >= 2
    assert any("x.json" in k for k in keys)
    delete_prefix("test/list/")


def test_tag_and_get_tags():
    key = "test/tag/item.json"
    upload_bytes(key, b"{}")
    tag_object(key, {"status": "ingested", "tool": "dependencies"})
    tags = get_object_tags(key)
    assert tags["status"] == "ingested"
    assert tags["tool"] == "dependencies"
    delete_prefix("test/tag/")


def test_download_missing_returns_none():
    result = download_bytes("nonexistent/key/file.json")
    assert result is None


def test_download_json_missing_returns_none():
    result = download_json("nonexistent/key/file.json")
    assert result is None
