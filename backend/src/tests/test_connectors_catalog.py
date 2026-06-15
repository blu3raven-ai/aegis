from __future__ import annotations

import pytest

from src.connectors.base import BaseSender, TestResult
from src.connectors.catalog import serialize_catalog
from src.connectors.registry import register_connector, _reset_registry


@pytest.fixture(autouse=True)
def clean_registry():
    _reset_registry()
    yield
    _reset_registry()


def test_empty_registry_serializes_to_empty_list():
    assert serialize_catalog() == []


def test_single_connector_serializes_with_all_metadata():
    @register_connector
    class SlackLike(BaseSender):
        id = "slacklike"
        name = "Slack-like"
        category = "notification"
        description = "Post things to a channel"
        version = "v1.0"
        status = "stable"
        icon_slug = "slack"
        href = "/notifications"

        def send(self, payload: dict) -> dict:
            return payload

        def test(self) -> TestResult:
            return TestResult(ok=True)

    catalog = serialize_catalog()
    assert catalog == [
        {
            "id": "slacklike",
            "name": "Slack-like",
            "kind": "sender",
            "category": "notification",
            "description": "Post things to a channel",
            "version": "v1.0",
            "status": "stable",
            "icon_slug": "slack",
            "href": "/notifications",
        }
    ]


def test_connector_without_href_serializes_null():
    @register_connector
    class NoHref(BaseSender):
        id = "nohref"
        name = "No Href"
        category = "ci"
        description = "no href"
        version = "v0.1"
        status = "preview"
        icon_slug = "nohref"

        def send(self, payload: dict) -> dict:
            return payload

        def test(self) -> TestResult:
            return TestResult(ok=True)

    catalog = serialize_catalog()
    assert catalog[0]["href"] is None
