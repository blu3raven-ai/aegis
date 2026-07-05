"""Azure DevOps Services webhook ingester contract.

Mirrors the github/gitlab/bitbucket provider tests:
- Basic-auth verification primitive (valid / wrong / missing / malformed)
- Per-event normalization (push, pullrequest.created, pullrequest.updated)
- End-to-end signed POST -> bus -> WebhookScanDispatcher -> submit_ci_scan
"""
from __future__ import annotations

import asyncio
import base64
import json
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Any
from unittest.mock import AsyncMock, patch

from fastapi import FastAPI
from fastapi.testclient import TestClient

from src.connectors.registry import get_connector
from src.connectors.webhooks import event_listener as listener_mod
from src.connectors.webhooks.event_listener import WebhookScanDispatcher
from src.connectors.webhooks.normalizer import normalize_azure_pr, normalize_azure_push
from src.connectors.webhooks.signature import verify_basic_auth


_SECRET = "user:s3cret"


def _basic_header(secret: str = _SECRET) -> str:
    return "Basic " + base64.b64encode(secret.encode()).decode()


# ── Signature primitive: verify_basic_auth ────────────────────────────────────


def test_basic_auth_accepts_valid_header():
    assert verify_basic_auth(_SECRET, _basic_header()) is True


def test_basic_auth_rejects_wrong_secret():
    assert verify_basic_auth("user:other", _basic_header()) is False


def test_basic_auth_rejects_empty_header():
    assert verify_basic_auth(_SECRET, "") is False


def test_basic_auth_rejects_missing_prefix():
    raw = base64.b64encode(_SECRET.encode()).decode()
    assert verify_basic_auth(_SECRET, raw) is False


def test_basic_auth_rejects_malformed_base64():
    assert verify_basic_auth(_SECRET, "Basic !!!not-base64!!!") is False


def test_basic_auth_rejects_empty_base64_payload():
    assert verify_basic_auth(_SECRET, "Basic ") is False


def test_basic_auth_rejects_empty_secret():
    assert verify_basic_auth("", _basic_header("anything:x")) is False


# ── Ingester registry contract ────────────────────────────────────────────────


def test_azure_devops_ingester_registered():
    from src.connectors.webhooks.providers import azure_devops as _ado
    cls = get_connector("azure-devops-webhook")
    assert cls is _ado.AzureDevOpsIngester
    assert cls.kind == "ingester"
    assert cls.category == "ci"
    assert cls.icon_slug == "azuredevops"


def test_azure_devops_signature_header_name():
    from src.connectors.webhooks.providers import azure_devops as _ado
    assert _ado.AzureDevOpsIngester().signature_header() == "Authorization"


def test_azure_devops_verify_signature_routes_through_env(monkeypatch):
    from src.connectors.webhooks.providers import azure_devops as _ado
    monkeypatch.setenv("AZURE_DEVOPS_WEBHOOK_SECRET", _SECRET)
    ing = _ado.AzureDevOpsIngester()
    assert ing.verify_signature(b"ignored", _basic_header()) is True
    assert ing.verify_signature(b"ignored", _basic_header("user:wrong")) is False


def test_azure_devops_verify_signature_env_missing_fails_closed(monkeypatch):
    from src.connectors.webhooks.providers import azure_devops as _ado
    monkeypatch.delenv("AZURE_DEVOPS_WEBHOOK_SECRET", raising=False)
    assert _ado.AzureDevOpsIngester().verify_signature(b"x", _basic_header()) is False


def test_azure_devops_test_reports_secret_missing(monkeypatch):
    from src.connectors.webhooks.providers import azure_devops as _ado
    monkeypatch.delenv("AZURE_DEVOPS_WEBHOOK_SECRET", raising=False)
    result = _ado.AzureDevOpsIngester().test()
    assert result.ok is False
    assert "AZURE_DEVOPS_WEBHOOK_SECRET" in (result.message or "")


# ── Payload fixtures ──────────────────────────────────────────────────────────


def _push_payload() -> dict[str, Any]:
    """Representative `git.push` payload from Azure DevOps Services docs."""
    return {
        "eventType": "git.push",
        "resource": {
            "commits": [
                {
                    "commitId": "a" * 40,
                    "author": {"name": "Alice", "email": "alice@example.com"},
                    "comment": "feat: x",
                },
            ],
            "refUpdates": [
                {
                    "name": "refs/heads/main",
                    "oldObjectId": "0" * 40,
                    "newObjectId": "a" * 40,
                },
            ],
            "repository": {
                "name": "payments-api",
                "project": {"name": "platform"},
                "remoteUrl": "https://dev.azure.com/acme-org/platform/_git/payments-api",
            },
            "pushedBy": {
                "displayName": "Alice",
                "uniqueName": "alice@example.com",
            },
        },
    }


def _pr_payload(event_type: str = "git.pullrequest.created") -> dict[str, Any]:
    return {
        "eventType": event_type,
        "resource": {
            "pullRequestId": 42,
            "title": "feat: add x",
            "sourceRefName": "refs/heads/feature/x",
            "targetRefName": "refs/heads/main",
            "lastMergeSourceCommit": {"commitId": "c" * 40},
            "lastMergeTargetCommit": {"commitId": "b" * 40},
            "repository": {
                "name": "payments-api",
                "project": {"name": "platform"},
                "remoteUrl": "https://dev.azure.com/acme-org/platform/_git/payments-api",
            },
            "createdBy": {
                "displayName": "Alice",
                "uniqueName": "alice@example.com",
            },
        },
    }


# ── normalize_azure_push ──────────────────────────────────────────────────────


def test_normalize_push_extracts_canonical_fields():
    event = normalize_azure_push(_push_payload())
    assert event.event_type == "code.push"
    assert event.source_component == "integrations.azure_devops"
    p = event.payload
    assert p["repo_id"] == "platform/payments-api"
    assert p["ref"] == "refs/heads/main"
    assert p["after_sha"] == "a" * 40
    # all-zero old SHA (new branch) collapses to None so the dispatcher
    # treats it the same as the other providers' new-branch case.
    assert p["before_sha"] is None
    assert p["commits"] == [{"sha": "a" * 40, "author": "alice@example.com"}]
    assert p["author"] == "alice@example.com"


def test_normalize_push_preserves_non_zero_before_sha():
    payload = _push_payload()
    payload["resource"]["refUpdates"][0]["oldObjectId"] = "9" * 40
    event = normalize_azure_push(payload)
    assert event.payload["before_sha"] == "9" * 40


def test_normalize_push_handles_missing_commits():
    payload = _push_payload()
    payload["resource"].pop("commits")
    event = normalize_azure_push(payload)
    assert event.payload["commits"] == []


# ── normalize_azure_pr ────────────────────────────────────────────────────────


def test_normalize_pr_created_emits_pr_opened():
    event = normalize_azure_pr(_pr_payload("git.pullrequest.created"), opened=True)
    assert event.event_type == "code.pr_opened"
    assert event.source_component == "integrations.azure_devops"
    p = event.payload
    assert p["repo_id"] == "platform/payments-api"
    assert p["pr_number"] == 42
    assert p["base_sha"] == "b" * 40
    assert p["head_sha"] == "c" * 40
    assert p["author"] == "alice@example.com"
    assert p["title"] == "feat: add x"
    assert p["source_ref"] == "refs/heads/feature/x"
    assert p["target_ref"] == "refs/heads/main"


def test_normalize_pr_updated_emits_pr_updated():
    event = normalize_azure_pr(_pr_payload("git.pullrequest.updated"), opened=False)
    assert event.event_type == "code.pr_updated"
    assert event.payload["pr_number"] == 42


# ── HTTP handler: signature gating ────────────────────────────────────────────


@dataclass
class _FakeAsset:
    id: str
    external_ref: str
    archived: bool = False


def _fake_session(asset: _FakeAsset | None):
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
    from src.connectors.webhooks.providers.azure_devops import router as ado_router

    app = FastAPI()
    app.include_router(ado_router)
    return app


def test_webhook_rejects_wrong_secret(monkeypatch):
    monkeypatch.setenv("AZURE_DEVOPS_WEBHOOK_SECRET", _SECRET)
    app = _build_app()
    client = TestClient(app)
    body = json.dumps(_push_payload()).encode()

    resp = client.post(
        "/integrations/azure-devops/webhook",
        content=body,
        headers={
            "Authorization": _basic_header("user:nope"),
            "Content-Type": "application/json",
        },
    )
    assert resp.status_code == 401


def test_webhook_rejects_missing_authorization_header(monkeypatch):
    monkeypatch.setenv("AZURE_DEVOPS_WEBHOOK_SECRET", _SECRET)
    app = _build_app()
    client = TestClient(app)
    body = json.dumps(_push_payload()).encode()

    # FastAPI's Header(...) with no default returns 422 when entirely missing;
    # confirm the route does not accept an unauthenticated request.
    resp = client.post(
        "/integrations/azure-devops/webhook",
        content=body,
        headers={"Content-Type": "application/json"},
    )
    assert resp.status_code in (401, 422)


def test_webhook_rejects_malformed_base64(monkeypatch):
    monkeypatch.setenv("AZURE_DEVOPS_WEBHOOK_SECRET", _SECRET)
    app = _build_app()
    client = TestClient(app)
    body = json.dumps(_push_payload()).encode()

    resp = client.post(
        "/integrations/azure-devops/webhook",
        content=body,
        headers={
            "Authorization": "Basic !!!not-base64!!!",
            "Content-Type": "application/json",
        },
    )
    assert resp.status_code == 401


def test_webhook_ignores_unsupported_event_type(monkeypatch):
    monkeypatch.setenv("AZURE_DEVOPS_WEBHOOK_SECRET", _SECRET)
    app = _build_app()
    client = TestClient(app)
    body = json.dumps({"eventType": "build.complete"}).encode()

    resp = client.post(
        "/integrations/azure-devops/webhook",
        content=body,
        headers={
            "Authorization": _basic_header(),
            "Content-Type": "application/json",
        },
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == "ignored"


def test_webhook_returns_400_for_invalid_json(monkeypatch):
    monkeypatch.setenv("AZURE_DEVOPS_WEBHOOK_SECRET", _SECRET)
    app = _build_app()
    client = TestClient(app)

    resp = client.post(
        "/integrations/azure-devops/webhook",
        content=b"not-json",
        headers={
            "Authorization": _basic_header(),
            "Content-Type": "application/json",
        },
    )
    assert resp.status_code == 400


# ── End-to-end: signed POST -> bus -> dispatch ─────────────────────────────────


def test_signed_azure_push_triggers_dispatch(monkeypatch):
    monkeypatch.setenv("AEGIS_WEBHOOK_DISPATCH_ENABLED", "true")
    monkeypatch.setenv("AZURE_DEVOPS_WEBHOOK_SECRET", _SECRET)

    asset = _FakeAsset(id="asset-ado", external_ref="azure_devops:platform/payments-api")
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
                    "/integrations/azure-devops/webhook",
                    content=body,
                    headers={
                        "Authorization": _basic_header(),
                        "Content-Type": "application/json",
                    },
                )
                assert resp.status_code == 200, resp.text
                assert resp.json()["status"] == "accepted"

                for _ in range(50):
                    await asyncio.sleep(0.01)
                    if submitted:
                        break
        finally:
            dispatcher.stop()

    asyncio.run(_run())

    assert len(submitted) == 1
    kwargs = submitted[0]
    assert kwargs["source_id"] == "asset-ado"
    assert kwargs["commit_sha"] == "a" * 40
    assert kwargs["branch"] == "main"
    assert kwargs["pr_number"] is None
    assert kwargs["triggered_by"] == "webhook"
    meta = kwargs["trigger_metadata"]
    assert meta["provider"] == "azure_devops"
    assert meta["event_type"] == "code.push"


def test_signed_azure_pr_triggers_dispatch(monkeypatch):
    monkeypatch.setenv("AEGIS_WEBHOOK_DISPATCH_ENABLED", "true")
    monkeypatch.setenv("AZURE_DEVOPS_WEBHOOK_SECRET", _SECRET)

    asset = _FakeAsset(id="asset-ado-pr", external_ref="azure_devops:platform/payments-api")
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
            body = json.dumps(_pr_payload("git.pullrequest.created")).encode()
            with (
                patch.object(listener_mod, "get_session", _fake_session(asset)),
                patch.object(listener_mod, "find_inflight_scan", new=AsyncMock(return_value=None)),
                patch.object(listener_mod, "submit_ci_scan", side_effect=fake_submit),
            ):
                resp = client.post(
                    "/integrations/azure-devops/webhook",
                    content=body,
                    headers={
                        "Authorization": _basic_header(),
                        "Content-Type": "application/json",
                    },
                )
                assert resp.status_code == 200, resp.text
                for _ in range(50):
                    await asyncio.sleep(0.01)
                    if submitted:
                        break
        finally:
            dispatcher.stop()

    asyncio.run(_run())

    assert len(submitted) == 1
    kwargs = submitted[0]
    assert kwargs["source_id"] == "asset-ado-pr"
    assert kwargs["commit_sha"] == "c" * 40
    assert kwargs["pr_number"] == 42
    assert kwargs["branch"] is None
    meta = kwargs["trigger_metadata"]
    assert meta["provider"] == "azure_devops"
    assert meta["event_type"] == "code.pr_opened"


def test_invalid_basic_auth_rejected_and_no_dispatch(monkeypatch):
    monkeypatch.setenv("AEGIS_WEBHOOK_DISPATCH_ENABLED", "true")
    monkeypatch.setenv("AZURE_DEVOPS_WEBHOOK_SECRET", _SECRET)

    asset = _FakeAsset(id="asset-x", external_ref="azure_devops:platform/payments-api")
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
                    "/integrations/azure-devops/webhook",
                    content=body,
                    headers={
                        "Authorization": _basic_header("user:wrong"),
                        "Content-Type": "application/json",
                    },
                )
                assert resp.status_code == 401
                await asyncio.sleep(0)
        finally:
            dispatcher.stop()

    asyncio.run(_run())
    assert submitted == []
