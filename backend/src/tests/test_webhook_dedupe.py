"""Inbound-webhook replay deduplication (RR-01).

DB-backed: exercises the real ``webhook_processed_deliveries`` unique
constraint through ``register_delivery`` and drives the github/gitlab
receivers end-to-end to prove a replayed, still-signed delivery is dropped
before republish.
"""
from __future__ import annotations

import hashlib
import hmac
import json
from datetime import timedelta
from typing import Any
from unittest.mock import MagicMock, patch
from uuid import uuid4

from fastapi import FastAPI
from fastapi.testclient import TestClient

from src.connectors.webhooks import dedupe
from src.connectors.webhooks.dedupe import prune_old_deliveries, register_delivery
from src.db.helpers import run_db
from src.db.models import WebhookProcessedDelivery, utcnow

_GH_SECRET = "test-webhook-secret"
_GL_TOKEN = "test-gitlab-token"


def _delete_all() -> None:
    from sqlalchemy import delete

    async def _q(session):
        await session.execute(delete(WebhookProcessedDelivery))

    run_db(_q)


def _row_count() -> int:
    from sqlalchemy import func, select

    async def _q(session):
        return (await session.execute(select(func.count()).select_from(WebhookProcessedDelivery))).scalar_one()

    return run_db(_q)


# --- register_delivery ------------------------------------------------------


def test_register_first_call_is_new_second_is_duplicate():
    _delete_all()
    did = uuid4().hex
    assert register_delivery("github", did) is False
    assert register_delivery("github", did) is True


def test_register_scoped_by_provider():
    _delete_all()
    did = uuid4().hex
    assert register_delivery("github", did) is False
    # Same delivery_id under a different provider is a distinct delivery.
    assert register_delivery("gitlab", did) is False
    # ...and each is now individually a duplicate.
    assert register_delivery("github", did) is True
    assert register_delivery("gitlab", did) is True


def test_register_sequential_same_key_false_then_true():
    _delete_all()
    did = uuid4().hex
    results = [register_delivery("bitbucket", did) for _ in range(2)]
    assert results == [False, True]


# --- prune_old_deliveries ---------------------------------------------------


def test_prune_deletes_old_keeps_fresh():
    _delete_all()
    old_id = uuid4().hex
    fresh_id = uuid4().hex

    async def _seed(session):
        session.add(
            WebhookProcessedDelivery(
                provider="github",
                delivery_id=old_id,
                received_at=utcnow() - timedelta(days=30),
            )
        )
        session.add(WebhookProcessedDelivery(provider="github", delivery_id=fresh_id))

    run_db(_seed)

    deleted = prune_old_deliveries(older_than_days=7)
    assert deleted == 1

    from sqlalchemy import select

    async def _remaining(session):
        rows = (await session.execute(select(WebhookProcessedDelivery.delivery_id))).scalars().all()
        return set(rows)

    remaining = run_db(_remaining)
    assert old_id not in remaining
    assert fresh_id in remaining


# --- receiver-level replay --------------------------------------------------


def _gh_sign(body: bytes) -> str:
    return "sha256=" + hmac.new(_GH_SECRET.encode(), body, hashlib.sha256).hexdigest()


def _gh_push_payload() -> dict[str, Any]:
    return {
        "ref": "refs/heads/main",
        "before": "0" * 40,
        "after": "1" * 40,
        "repository": {"name": "payments-api", "owner": {"login": "acme-org"}},
        "commits": [],
    }


def _gl_push_payload() -> dict[str, Any]:
    return {
        "object_kind": "push",
        "ref": "refs/heads/main",
        "before": "0" * 40,
        "after": "1" * 40,
        "checkout_sha": "1" * 40,
        "project": {"path_with_namespace": "acme-org/payments-api"},
        "commits": [],
    }


def test_github_replay_is_deduped(monkeypatch):
    monkeypatch.setenv("GITHUB_WEBHOOK_SECRET", _GH_SECRET)
    _delete_all()

    from src.connectors.webhooks.providers import github as gh

    app = FastAPI()
    app.include_router(gh.router)
    client = TestClient(app)

    body = json.dumps(_gh_push_payload()).encode()
    delivery_id = uuid4().hex
    headers = {
        "X-GitHub-Event": "push",
        "X-Hub-Signature-256": _gh_sign(body),
        "X-GitHub-Delivery": delivery_id,
        "Content-Type": "application/json",
    }

    publisher = MagicMock()
    with patch.object(gh, "get_event_publisher", return_value=publisher):
        first = client.post("/integrations/github/webhook", content=body, headers=headers)
        replay = client.post("/integrations/github/webhook", content=body, headers=headers)

    assert first.status_code == 200, first.text
    assert first.json()["status"] == "accepted"
    assert replay.status_code == 200, replay.text
    assert replay.json() == {"status": "duplicate", "event_id": None}
    # Published exactly once across the original + replay.
    assert publisher.publish.call_count == 1


def test_github_without_delivery_header_still_processes(monkeypatch):
    monkeypatch.setenv("GITHUB_WEBHOOK_SECRET", _GH_SECRET)
    _delete_all()

    from src.connectors.webhooks.providers import github as gh

    app = FastAPI()
    app.include_router(gh.router)
    client = TestClient(app)

    body = json.dumps(_gh_push_payload()).encode()
    headers = {
        "X-GitHub-Event": "push",
        "X-Hub-Signature-256": _gh_sign(body),
        "Content-Type": "application/json",
    }

    publisher = MagicMock()
    with patch.object(gh, "get_event_publisher", return_value=publisher):
        first = client.post("/integrations/github/webhook", content=body, headers=headers)
        second = client.post("/integrations/github/webhook", content=body, headers=headers)

    assert first.json()["status"] == "accepted"
    assert second.json()["status"] == "accepted"
    # No delivery id → no dedup → both publish.
    assert publisher.publish.call_count == 2
    # No rows recorded when the header is absent.
    assert _row_count() == 0


def test_gitlab_replay_is_deduped(monkeypatch):
    monkeypatch.setenv("GITLAB_WEBHOOK_SECRET", _GL_TOKEN)
    _delete_all()

    from src.connectors.webhooks.providers import gitlab as gl

    app = FastAPI()
    app.include_router(gl.router)
    client = TestClient(app)

    body = json.dumps(_gl_push_payload()).encode()
    delivery_id = uuid4().hex
    headers = {
        "X-Gitlab-Token": _GL_TOKEN,
        "X-Gitlab-Event": "Push Hook",
        "X-Gitlab-Event-UUID": delivery_id,
        "Content-Type": "application/json",
    }

    publisher = MagicMock()
    with patch.object(gl, "get_event_publisher", return_value=publisher):
        first = client.post("/integrations/gitlab/webhook", content=body, headers=headers)
        replay = client.post("/integrations/gitlab/webhook", content=body, headers=headers)

    assert first.status_code == 200, first.text
    assert first.json()["status"] == "accepted"
    assert replay.json() == {"status": "duplicate", "event_id": None}
    assert publisher.publish.call_count == 1


def test_prune_counter_threshold_constant():
    # Guard against an accidental change that would prune on every insert.
    assert dedupe._PRUNE_EVERY >= 100
