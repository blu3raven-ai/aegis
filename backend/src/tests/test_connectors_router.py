"""Smoke + shape tests for GET /api/v1/connectors."""
from __future__ import annotations

import importlib
import os

import pytest

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost:5432/test")
os.environ.setdefault("RUNNER_ENCRYPTION_KEY", "0" * 64)

from fastapi import FastAPI, Request  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from src.connectors.registry import _reset_registry  # noqa: E402
from src.connectors.router import router as connectors_router  # noqa: E402

# Pre-import all leaf modules so importlib.reload() can re-fire their decorators
# even after other test modules call _reset_registry() in their teardown.
import src.integrations.ci_wizards as _ci_wizards  # noqa: E402
import src.integrations.github_webhook as _gh_webhook  # noqa: E402
import src.integrations.gitlab_webhook as _gl_webhook  # noqa: E402
import src.integrations.bitbucket_webhook as _bb_webhook  # noqa: E402
import src.notifications.senders.slack as _slack  # noqa: E402
import src.notifications.senders.webhook as _webhook  # noqa: E402
import src.notifications.senders.email as _email  # noqa: E402
import src.notifications.senders.jira as _jira  # noqa: E402
import src.notifications.senders.linear as _linear  # noqa: E402
import src.notifications.senders.github_issues as _gh_issues  # noqa: E402
import src.runner.catalog_entry as _runner_entry  # noqa: E402

_ALL_MODULES = (
    _ci_wizards, _gh_webhook, _gl_webhook, _bb_webhook,
    _slack, _webhook, _email, _jira, _linear, _gh_issues,
    _runner_entry,
)


@pytest.fixture(autouse=True)
def _ensure_all_connectors_registered():
    """Guarantee every connector is in the registry before each test.

    Other test modules call _reset_registry() in their teardown, which empties
    the global dict. A plain re-import won't re-fire module-level decorators
    (modules are cached in sys.modules), so we must reset + reload to force
    re-registration — matching the pattern used by test_notifications_senders.
    """
    _reset_registry()
    for mod in _ALL_MODULES:
        importlib.reload(mod)
    yield


def _make_app() -> FastAPI:
    app = FastAPI()
    app.include_router(connectors_router)
    return app


def test_endpoint_returns_200_with_catalog_shape():
    app = _make_app()
    resp = TestClient(app).get("/api/v1/connectors")
    assert resp.status_code == 200
    body = resp.json()
    assert "connectors" in body
    assert "total" in body
    assert body["total"] == len(body["connectors"])


def test_endpoint_returns_all_kinds_registered():
    app = _make_app()
    resp = TestClient(app).get("/api/v1/connectors")
    kinds = {entry["kind"] for entry in resp.json()["connectors"]}
    assert kinds == {"sender", "ingester", "runner", "wizard"}


def test_endpoint_returns_at_least_15_entries():
    """6 senders + 3 ingesters + 1 runner + 5 wizards = 15. The count can
    grow in future PRs but should never regress below today's baseline."""
    app = _make_app()
    resp = TestClient(app).get("/api/v1/connectors")
    assert resp.json()["total"] >= 15


def test_endpoint_entries_have_required_metadata_fields():
    app = _make_app()
    resp = TestClient(app).get("/api/v1/connectors")
    required = {"id", "name", "kind", "category", "description", "version", "status", "icon_slug", "href"}
    for entry in resp.json()["connectors"]:
        missing = required - entry.keys()
        assert not missing, f"entry {entry.get('id')} missing fields: {missing}"
