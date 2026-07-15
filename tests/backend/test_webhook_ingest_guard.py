"""Tests for the inbound-webhook request guards (size cap + rate limit).

These protect the unauthenticated receiver routes: an oversized body is
rejected with 413 before any HMAC is computed, and a per-IP flood is
rejected with 429.
"""
from __future__ import annotations

from typing import AsyncIterator

import pytest
from fastapi import HTTPException

from src.connectors.webhooks.ingest_guard import (
    MAX_WEBHOOK_BODY_BYTES,
    parse_json_object,
    read_guarded_body,
)
from src.shared import rate_limit as rate_limit_mod


class _FakeClient:
    def __init__(self, host: str) -> None:
        self.host = host


class _FakeRequest:
    """Minimal stand-in exposing only what ``read_guarded_body`` touches."""

    def __init__(
        self,
        *,
        host: str,
        chunks: list[bytes],
        content_length: str | None = None,
    ) -> None:
        self.client = _FakeClient(host)
        headers = {}
        if content_length is not None:
            headers["content-length"] = content_length
        self.headers = headers
        self._chunks = chunks
        self.stream_consumed = False

    async def stream(self) -> AsyncIterator[bytes]:
        self.stream_consumed = True
        for chunk in self._chunks:
            yield chunk


def _reset_ip(host: str) -> None:
    rate_limit_mod._buckets.pop(f"ip:{host}", None)


@pytest.mark.asyncio
async def test_reads_small_body():
    _reset_ip("198.51.100.1")
    req = _FakeRequest(host="198.51.100.1", chunks=[b"hello ", b"world"])
    body = await read_guarded_body(req)
    assert body == b"hello world"


@pytest.mark.asyncio
async def test_oversized_content_length_rejected_before_reading():
    _reset_ip("198.51.100.2")
    req = _FakeRequest(
        host="198.51.100.2",
        chunks=[b"x"],
        content_length=str(MAX_WEBHOOK_BODY_BYTES + 1),
    )
    with pytest.raises(HTTPException) as exc:
        await read_guarded_body(req)
    assert exc.value.status_code == 413
    # HMAC is computed over the streamed body; rejecting on the declared
    # length means we never even read it.
    assert req.stream_consumed is False


@pytest.mark.asyncio
async def test_invalid_content_length_rejected():
    _reset_ip("198.51.100.5")
    req = _FakeRequest(host="198.51.100.5", chunks=[b"x"], content_length="not-a-number")
    with pytest.raises(HTTPException) as exc:
        await read_guarded_body(req)
    assert exc.value.status_code == 400
    assert req.stream_consumed is False


@pytest.mark.asyncio
async def test_streamed_body_over_ceiling_rejected():
    """Content-Length can be absent/understated under chunked encoding, so
    the ceiling is enforced again while streaming."""
    _reset_ip("198.51.100.3")
    half = MAX_WEBHOOK_BODY_BYTES // 2 + 1
    req = _FakeRequest(host="198.51.100.3", chunks=[b"a" * half, b"b" * half])
    with pytest.raises(HTTPException) as exc:
        await read_guarded_body(req)
    assert exc.value.status_code == 413


@pytest.mark.asyncio
async def test_rate_limit_trips_after_threshold():
    host = "203.0.113.77"
    _reset_ip(host)
    # The guard allows 60 requests per 60s window; the 61st trips.
    for _ in range(60):
        req = _FakeRequest(host=host, chunks=[b"{}"])
        assert await read_guarded_body(req) == b"{}"

    req = _FakeRequest(host=host, chunks=[b"{}"])
    with pytest.raises(HTTPException) as exc:
        await read_guarded_body(req)
    assert exc.value.status_code == 429
    _reset_ip(host)


def test_parse_json_object_returns_dict():
    assert parse_json_object(b'{"a": 1}') == {"a": 1}


def test_parse_json_object_rejects_invalid_json():
    with pytest.raises(HTTPException) as exc:
        parse_json_object(b"{not json")
    assert exc.value.status_code == 400
    assert exc.value.detail == "Invalid JSON body"


@pytest.mark.parametrize("body", [b"[]", b"5", b'"x"', b"null", b"true"])
def test_parse_json_object_rejects_valid_json_non_object(body: bytes):
    # A structurally valid but non-object body would break payload.get(...)
    # downstream — it must surface as a clean 400, never a 500.
    with pytest.raises(HTTPException) as exc:
        parse_json_object(body)
    assert exc.value.status_code == 400
    assert exc.value.detail == "JSON body must be an object"
