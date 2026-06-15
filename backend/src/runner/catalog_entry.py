"""Federated runner catalog entry — metadata only.

The actual runner protocol (workers, queue, heartbeat) lives elsewhere in
backend/src/runner/ and is unchanged. This module exists so the runner
appears in the kernel catalog uniformly with senders / ingesters / wizards."""
from __future__ import annotations

from src.connectors.base import BaseRunner, TestResult
from src.connectors.registry import register_connector


@register_connector
class FederatedRunner(BaseRunner):
    id = "federated-runner"
    name = "Federated Runner"
    category = "runner"
    description = "Run scans privately on your own infrastructure"
    version = "v1.0"
    status = "stable"
    icon_slug = "runner"
    href = "/settings/runners"

    def test(self) -> TestResult:
        return TestResult(ok=True)
