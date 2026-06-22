"""End-to-end: signed GitHub webhook POST -> bus -> WebhookScanDispatcher
-> submit_ci_scan (mocked).

This exercises the same wiring main.py installs at startup: the receiver
route publishes a typed event, the listener picks it up off the EventBus
and submits a scan.
"""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Any
from unittest.mock import AsyncMock, patch

from fastapi import FastAPI
from fastapi.testclient import TestClient

from src.connectors.webhooks import event_listener as listener_mod
from src.connectors.webhooks.event_listener import WebhookScanDispatcher


_SECRET = "test-webhook-secret"


def _sign(body: bytes, secret: str = _SECRET) -> str:
    return "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


def _push_payload() -> dict[str, Any]:
    return {
        "ref": "refs/heads/main",
        "before": "0" * 40,
        "after": "1" * 40,
        "repository": {
            "name": "payments-api",
            "owner": {"login": "acme-org"},
        },
        "commits": [],
    }


@dataclass
class _FakeAsset:
    id: str
    external_ref: str
    archived: bool = False


def _fake_session(asset: _FakeAsset):
    class _ScalarResult:
        def scalar_one_or_none(self) -> Any:
            return asset

    class _Session:
        async def execute(self, _stmt: Any) -> _ScalarResult:
            return _ScalarResult()

    @asynccontextmanager
    async def _ctx():
        yield _Session()

    return _ctx


def _build_app() -> FastAPI:
    from src.connectors.webhooks.providers.github import router as github_router

    app = FastAPI()
    app.include_router(github_router)
    return app


def test_signed_github_push_triggers_dispatch(monkeypatch):
    monkeypatch.setenv("AEGIS_WEBHOOK_DISPATCH_ENABLED", "true")
    monkeypatch.setenv("GITHUB_WEBHOOK_SECRET", _SECRET)

    asset = _FakeAsset(id="asset-e2e", external_ref="github:acme-org/payments-api")
    submitted: list[dict] = []

    async def fake_submit(**kwargs):
        submitted.append(kwargs)

    async def _run() -> None:
        from src.shared.event_bus import get_event_bus

        bus = get_event_bus()
        bus.set_loop(asyncio.get_running_loop())
        dispatcher = WebhookScanDispatcher(event_bus=bus)
        dispatcher.start()
        try:
            app = _build_app()
            client = TestClient(app)

            body = json.dumps(_push_payload()).encode()
            with (
                patch.object(listener_mod, "get_session", _fake_session(asset)),
                patch.object(listener_mod, "find_inflight_scan", new=AsyncMock(return_value=None)),
                patch.object(listener_mod, "submit_ci_scan", side_effect=fake_submit),
            ):
                resp = client.post(
                    "/integrations/github/webhook",
                    content=body,
                    headers={
                        "X-GitHub-Event": "push",
                        "X-Hub-Signature-256": _sign(body),
                        "Content-Type": "application/json",
                    },
                )
                assert resp.status_code == 200, resp.text
                assert resp.json()["status"] == "accepted"

                # The receiver hands off to the bus synchronously; the listener
                # then schedules dispatch onto the running loop. Yield until it
                # lands.
                for _ in range(50):
                    await asyncio.sleep(0.01)
                    if submitted:
                        break
        finally:
            dispatcher.stop()

    asyncio.run(_run())

    assert len(submitted) == 1
    kwargs = submitted[0]
    assert kwargs["source_id"] == "asset-e2e"
    assert kwargs["commit_sha"] == "1" * 40
    assert kwargs["branch"] == "main"
    assert kwargs["pr_number"] is None
    assert kwargs["triggered_by"] == "webhook"
    assert kwargs["org"] == "acme-org"
    meta = kwargs["trigger_metadata"]
    assert meta["provider"] == "github"
    assert meta["event_type"] == "code.push"


def test_invalid_signature_is_rejected_and_no_dispatch(monkeypatch):
    monkeypatch.setenv("AEGIS_WEBHOOK_DISPATCH_ENABLED", "true")
    monkeypatch.setenv("GITHUB_WEBHOOK_SECRET", _SECRET)

    asset = _FakeAsset(id="asset-x", external_ref="github:acme-org/payments-api")
    submitted: list[dict] = []

    async def fake_submit(**kwargs):
        submitted.append(kwargs)

    async def _run() -> None:
        from src.shared.event_bus import get_event_bus

        bus = get_event_bus()
        bus.set_loop(asyncio.get_running_loop())
        dispatcher = WebhookScanDispatcher(event_bus=bus)
        dispatcher.start()
        try:
            app = _build_app()
            client = TestClient(app)
            body = json.dumps(_push_payload()).encode()
            with (
                patch.object(listener_mod, "get_session", _fake_session(asset)),
                patch.object(listener_mod, "find_inflight_scan", new=AsyncMock(return_value=None)),
                patch.object(listener_mod, "submit_ci_scan", side_effect=fake_submit),
            ):
                resp = client.post(
                    "/integrations/github/webhook",
                    content=body,
                    headers={
                        "X-GitHub-Event": "push",
                        "X-Hub-Signature-256": _sign(body, secret="wrong"),
                        "Content-Type": "application/json",
                    },
                )
                assert resp.status_code == 401
                # A rejected request never publishes; yield once so any in-flight
                # scheduling on the loop has a chance to surface (it won't).
                await asyncio.sleep(0)
        finally:
            dispatcher.stop()

    asyncio.run(_run())
    assert submitted == []
