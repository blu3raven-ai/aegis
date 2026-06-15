from __future__ import annotations

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from src.connectors.base import BaseIngester, TestResult
from src.connectors.webhooks.handler import webhook_handler


class _RecordingIngester(BaseIngester):
    """Test double: records normalize() calls; verify_signature returns
    True only if header == 'valid'."""
    id = "test-ingester"
    name = "Test Ingester"
    category = "ci"
    description = "test"
    version = "v0.1"
    status = "preview"
    icon_slug = "test"

    def signature_header(self) -> str:
        return "X-Test-Signature"

    def verify_signature(self, body: bytes, header: str) -> bool:
        return header == "valid"

    def normalize(self, body: bytes) -> dict:
        import json
        return json.loads(body)

    def test(self) -> TestResult:
        return TestResult(ok=True)


def _build_app(publish_calls: list) -> FastAPI:
    """Build a minimal FastAPI app that mounts the handler at /hook."""
    app = FastAPI()
    ingester = _RecordingIngester()

    async def fake_publish(event: object) -> None:
        publish_calls.append(event)

    @app.post("/hook")
    async def hook(request: Request):
        return await webhook_handler(request, ingester, publish=fake_publish)

    return app


def test_valid_signature_publishes_and_returns_accepted():
    publish_calls: list = []
    client = TestClient(_build_app(publish_calls))
    resp = client.post(
        "/hook",
        content=b'{"event":"push"}',
        headers={"X-Test-Signature": "valid"},
    )
    assert resp.status_code == 200
    assert resp.json() == {"status": "accepted"}
    assert publish_calls == [{"event": "push"}]


def test_invalid_signature_returns_401_and_does_not_publish():
    publish_calls: list = []
    client = TestClient(_build_app(publish_calls))
    resp = client.post(
        "/hook",
        content=b'{"event":"push"}',
        headers={"X-Test-Signature": "wrong"},
    )
    assert resp.status_code == 401
    assert publish_calls == []


def test_missing_signature_header_returns_401():
    publish_calls: list = []
    client = TestClient(_build_app(publish_calls))
    resp = client.post("/hook", content=b'{"event":"push"}')
    assert resp.status_code == 401
    assert publish_calls == []


def test_bad_json_after_valid_signature_returns_400():
    publish_calls: list = []
    client = TestClient(_build_app(publish_calls))
    resp = client.post(
        "/hook",
        content=b"not json",
        headers={"X-Test-Signature": "valid"},
    )
    assert resp.status_code == 400
    assert publish_calls == []
