"""Jenkins webhook ingester contract.

Mirrors the github/gitlab/bitbucket provider tests:
- Bearer-token verification primitive (valid / wrong / missing / malformed)
- Per-event normalization (Notification Plugin STARTED / FINALIZED)
- End-to-end signed POST -> bus -> WebhookScanDispatcher -> submit_ci_scan
"""
from __future__ import annotations

import asyncio
import importlib
import json
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from src.connectors.registry import get_connector
from src.connectors.webhooks import event_listener as listener_mod
from src.connectors.webhooks.event_listener import WebhookScanDispatcher
from src.connectors.webhooks.normalizer import normalize_jenkins_build
from src.connectors.webhooks.signature import verify_bearer_token


@pytest.fixture(autouse=True)
def _ensure_jenkins_ingester_registered():
    """Re-register the Jenkins ingester before each test.

    Other test modules (test_connectors_catalog, test_notifications_senders)
    call ``_reset_registry()`` in their teardown, which wipes the global
    dict. Module-level ``@register_connector`` decorators do not re-run on
    a plain re-import because Python caches modules in ``sys.modules`` —
    so we must explicitly reload the provider module to force the class
    back into the registry.
    """
    from src.connectors import registry as _registry
    import src.connectors.webhooks.providers.jenkins as _jen

    if "jenkins-webhook" not in _registry._REGISTRY:
        importlib.reload(_jen)
    yield


_SECRET = "j3nk1ns-token"


def _bearer_header(secret: str = _SECRET) -> str:
    return f"Bearer {secret}"


# ── Signature primitive: verify_bearer_token ──────────────────────────────────


def test_bearer_token_accepts_valid_header():
    assert verify_bearer_token(_SECRET, _bearer_header()) is True


def test_bearer_token_rejects_wrong_secret():
    assert verify_bearer_token("other-token", _bearer_header()) is False


def test_bearer_token_rejects_empty_header():
    assert verify_bearer_token(_SECRET, "") is False


def test_bearer_token_rejects_missing_prefix():
    assert verify_bearer_token(_SECRET, _SECRET) is False


def test_bearer_token_rejects_case_mismatched_prefix():
    assert verify_bearer_token(_SECRET, f"bearer {_SECRET}") is False


def test_bearer_token_rejects_empty_token_payload():
    assert verify_bearer_token(_SECRET, "Bearer ") is False


def test_bearer_token_rejects_empty_secret():
    assert verify_bearer_token("", _bearer_header("anything")) is False


# ── Ingester registry contract ────────────────────────────────────────────────


def test_jenkins_ingester_registered():
    from src.connectors.webhooks.providers import jenkins as _jen
    cls = get_connector("jenkins-webhook")
    assert cls is _jen.JenkinsIngester
    assert cls.kind == "ingester"
    assert cls.category == "ci"
    assert cls.icon_slug == "jenkins"


def test_jenkins_signature_header_name():
    from src.connectors.webhooks.providers import jenkins as _jen
    assert _jen.JenkinsIngester().signature_header() == "Authorization"


def test_jenkins_verify_signature_routes_through_env(monkeypatch):
    from src.connectors.webhooks.providers import jenkins as _jen
    monkeypatch.setenv("JENKINS_WEBHOOK_SECRET", _SECRET)
    ing = _jen.JenkinsIngester()
    assert ing.verify_signature(b"ignored", _bearer_header()) is True
    assert ing.verify_signature(b"ignored", _bearer_header("wrong")) is False


def test_jenkins_verify_signature_env_missing_fails_closed(monkeypatch):
    from src.connectors.webhooks.providers import jenkins as _jen
    monkeypatch.delenv("JENKINS_WEBHOOK_SECRET", raising=False)
    assert _jen.JenkinsIngester().verify_signature(b"x", _bearer_header()) is False


def test_jenkins_test_reports_secret_missing(monkeypatch):
    from src.connectors.webhooks.providers import jenkins as _jen
    monkeypatch.delenv("JENKINS_WEBHOOK_SECRET", raising=False)
    result = _jen.JenkinsIngester().test()
    assert result.ok is False
    assert "JENKINS_WEBHOOK_SECRET" in (result.message or "")


# ── Payload fixtures ──────────────────────────────────────────────────────────


def _build_payload(
    *,
    phase: str = "STARTED",
    status: str | None = None,
    branch: str = "origin/main",
    commit: str = "a" * 40,
    name: str = "my-pipeline",
    full_url: str = "https://jenkins.example.com/job/my-pipeline/42/",
    scm_url: str = "https://github.com/acme-org/my-repo.git",
) -> dict[str, Any]:
    """Representative Jenkins Notification Plugin payload."""
    return {
        "name": name,
        "url": f"job/{name}/",
        "build": {
            "full_url": full_url,
            "number": 42,
            "phase": phase,
            "status": status,
            "url": f"job/{name}/42/",
            "scm": {
                "url": scm_url,
                "branch": branch,
                "commit": commit,
                "changes": [],
            },
            "timestamp": 1718545200,
            "duration": 0,
        },
    }


# ── normalize_jenkins_build ───────────────────────────────────────────────────


def test_normalize_extracts_canonical_fields():
    event = normalize_jenkins_build(_build_payload())
    assert event.event_type == "code.push"
    assert event.source_component == "integrations.jenkins"
    p = event.payload
    assert p["repo_id"] == "jenkins.example.com/my-pipeline"
    assert p["ref"] == "refs/heads/main"
    assert p["after_sha"] == "a" * 40
    assert p["before_sha"] is None
    assert p["commits"] == []
    assert p["scm_url"] == "https://github.com/acme-org/my-repo.git"
    assert p["build_number"] == 42
    assert p["build_phase"] == "STARTED"


def test_normalize_handles_nested_job_path():
    event = normalize_jenkins_build(_build_payload(name="folder/sub/my-pipeline"))
    # The host/job_name composite must preserve the full folder path so the
    # dispatcher's rpartition split keeps the trailing job-name segment.
    assert event.payload["repo_id"] == "jenkins.example.com/folder/sub/my-pipeline"


def test_normalize_preserves_ref_when_already_prefixed():
    event = normalize_jenkins_build(_build_payload(branch="refs/tags/v1.2.3"))
    assert event.payload["ref"] == "refs/tags/v1.2.3"


def test_normalize_handles_non_origin_remote():
    # Anything without a `refs/` prefix becomes `refs/heads/<branch>`; only
    # the default `origin/` is stripped because that is what the git plugin
    # emits by default.
    event = normalize_jenkins_build(_build_payload(branch="upstream/main"))
    assert event.payload["ref"] == "refs/heads/upstream/main"


def test_normalize_handles_missing_branch():
    payload = _build_payload()
    payload["build"]["scm"]["branch"] = None
    event = normalize_jenkins_build(payload)
    assert event.payload["ref"] is None


def test_normalize_handles_malformed_full_url():
    payload = _build_payload(full_url="not-a-url")
    event = normalize_jenkins_build(payload)
    # urlparse returns an empty netloc for a path-only URL; the repo_id
    # falls back to just the job name (still routable if the operator
    # registered their source that way).
    assert event.payload["repo_id"] == "my-pipeline"


# ── HTTP handler ──────────────────────────────────────────────────────────────


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
    from src.connectors.webhooks.providers.jenkins import router as jenkins_router

    app = FastAPI()
    app.include_router(jenkins_router)
    return app


def test_webhook_rejects_wrong_secret(monkeypatch):
    monkeypatch.setenv("JENKINS_WEBHOOK_SECRET", _SECRET)
    app = _build_app()
    client = TestClient(app)
    body = json.dumps(_build_payload()).encode()

    resp = client.post(
        "/integrations/jenkins/webhook",
        content=body,
        headers={
            "Authorization": _bearer_header("nope"),
            "Content-Type": "application/json",
        },
    )
    assert resp.status_code == 401


def test_webhook_rejects_missing_authorization_header(monkeypatch):
    monkeypatch.setenv("JENKINS_WEBHOOK_SECRET", _SECRET)
    app = _build_app()
    client = TestClient(app)
    body = json.dumps(_build_payload()).encode()

    # FastAPI's Header(...) with no default returns 422 when entirely missing;
    # confirm the route does not accept an unauthenticated request.
    resp = client.post(
        "/integrations/jenkins/webhook",
        content=body,
        headers={"Content-Type": "application/json"},
    )
    assert resp.status_code in (401, 422)


def test_webhook_rejects_lowercase_bearer_prefix(monkeypatch):
    monkeypatch.setenv("JENKINS_WEBHOOK_SECRET", _SECRET)
    app = _build_app()
    client = TestClient(app)
    body = json.dumps(_build_payload()).encode()

    resp = client.post(
        "/integrations/jenkins/webhook",
        content=body,
        headers={
            "Authorization": f"bearer {_SECRET}",
            "Content-Type": "application/json",
        },
    )
    assert resp.status_code == 401


def test_webhook_ignores_completed_phase(monkeypatch):
    monkeypatch.setenv("JENKINS_WEBHOOK_SECRET", _SECRET)
    app = _build_app()
    client = TestClient(app)
    body = json.dumps(_build_payload(phase="COMPLETED", status="SUCCESS")).encode()

    resp = client.post(
        "/integrations/jenkins/webhook",
        content=body,
        headers={
            "Authorization": _bearer_header(),
            "Content-Type": "application/json",
        },
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == "ignored"


def test_webhook_ignores_finalized_failure(monkeypatch):
    monkeypatch.setenv("JENKINS_WEBHOOK_SECRET", _SECRET)
    app = _build_app()
    client = TestClient(app)
    body = json.dumps(_build_payload(phase="FINALIZED", status="FAILURE")).encode()

    resp = client.post(
        "/integrations/jenkins/webhook",
        content=body,
        headers={
            "Authorization": _bearer_header(),
            "Content-Type": "application/json",
        },
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == "ignored"


def test_webhook_ignores_payload_without_commit(monkeypatch):
    monkeypatch.setenv("JENKINS_WEBHOOK_SECRET", _SECRET)
    app = _build_app()
    client = TestClient(app)
    body = json.dumps(_build_payload(commit="")).encode()

    resp = client.post(
        "/integrations/jenkins/webhook",
        content=body,
        headers={
            "Authorization": _bearer_header(),
            "Content-Type": "application/json",
        },
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == "ignored"


def test_webhook_returns_400_for_invalid_json(monkeypatch):
    monkeypatch.setenv("JENKINS_WEBHOOK_SECRET", _SECRET)
    app = _build_app()
    client = TestClient(app)

    resp = client.post(
        "/integrations/jenkins/webhook",
        content=b"not-json",
        headers={
            "Authorization": _bearer_header(),
            "Content-Type": "application/json",
        },
    )
    assert resp.status_code == 400


# ── End-to-end: signed POST -> bus -> dispatch ─────────────────────────────────


def test_signed_jenkins_started_triggers_dispatch(monkeypatch):
    monkeypatch.setenv("AEGIS_WEBHOOK_DISPATCH_ENABLED", "true")
    monkeypatch.setenv("JENKINS_WEBHOOK_SECRET", _SECRET)

    asset = _FakeAsset(
        id="asset-jen",
        external_ref="jenkins:jenkins.example.com/my-pipeline",
    )
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
            body = json.dumps(_build_payload(phase="STARTED")).encode()
            with (
                patch.object(listener_mod, "get_session", _fake_session(asset)),
                patch.object(listener_mod, "find_inflight_scan", new=AsyncMock(return_value=None)),
                patch.object(listener_mod, "submit_ci_scan", side_effect=fake_submit),
            ):
                resp = client.post(
                    "/integrations/jenkins/webhook",
                    content=body,
                    headers={
                        "Authorization": _bearer_header(),
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
    assert kwargs["source_id"] == "asset-jen"
    assert kwargs["commit_sha"] == "a" * 40
    assert kwargs["branch"] == "main"
    assert kwargs["pr_number"] is None
    assert kwargs["triggered_by"] == "webhook"
    meta = kwargs["trigger_metadata"]
    assert meta["provider"] == "jenkins"
    assert meta["event_type"] == "code.push"


def test_signed_jenkins_finalized_success_triggers_dispatch(monkeypatch):
    monkeypatch.setenv("AEGIS_WEBHOOK_DISPATCH_ENABLED", "true")
    monkeypatch.setenv("JENKINS_WEBHOOK_SECRET", _SECRET)

    asset = _FakeAsset(
        id="asset-jen-success",
        external_ref="jenkins:jenkins.example.com/my-pipeline",
    )
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
            body = json.dumps(
                _build_payload(phase="FINALIZED", status="SUCCESS")
            ).encode()
            with (
                patch.object(listener_mod, "get_session", _fake_session(asset)),
                patch.object(listener_mod, "find_inflight_scan", new=AsyncMock(return_value=None)),
                patch.object(listener_mod, "submit_ci_scan", side_effect=fake_submit),
            ):
                resp = client.post(
                    "/integrations/jenkins/webhook",
                    content=body,
                    headers={
                        "Authorization": _bearer_header(),
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
    assert submitted[0]["source_id"] == "asset-jen-success"
    assert submitted[0]["trigger_metadata"]["provider"] == "jenkins"


def test_invalid_bearer_token_rejected_and_no_dispatch(monkeypatch):
    monkeypatch.setenv("AEGIS_WEBHOOK_DISPATCH_ENABLED", "true")
    monkeypatch.setenv("JENKINS_WEBHOOK_SECRET", _SECRET)

    asset = _FakeAsset(
        id="asset-x",
        external_ref="jenkins:jenkins.example.com/my-pipeline",
    )
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
            body = json.dumps(_build_payload()).encode()
            with (
                patch.object(listener_mod, "get_session", _fake_session(asset)),
                patch.object(listener_mod, "find_inflight_scan", new=AsyncMock(return_value=None)),
                patch.object(listener_mod, "submit_ci_scan", side_effect=fake_submit),
            ):
                resp = client.post(
                    "/integrations/jenkins/webhook",
                    content=body,
                    headers={
                        "Authorization": _bearer_header("wrong"),
                        "Content-Type": "application/json",
                    },
                )
                assert resp.status_code == 401
                await asyncio.sleep(0)
        finally:
            dispatcher.stop()

    asyncio.run(_run())
    assert submitted == []
