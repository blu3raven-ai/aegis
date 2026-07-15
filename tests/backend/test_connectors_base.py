from __future__ import annotations

import pytest
from src.connectors.base import BaseConnector, TestResult


def test_test_result_ok_without_message():
    result = TestResult(ok=True)
    assert result.ok is True
    assert result.message is None


def test_test_result_with_failure_message():
    result = TestResult(ok=False, message="endpoint returned 500")
    assert result.ok is False
    assert result.message == "endpoint returned 500"


def test_send_result_failure_with_error_message():
    from src.connectors.base import SendResult
    result = SendResult(success=False, response_code=503, error="upstream timeout")
    assert result.success is False
    assert result.response_code == 503
    assert result.error == "upstream timeout"


def test_base_connector_cannot_be_instantiated_directly():
    with pytest.raises(TypeError):
        BaseConnector()  # type: ignore[abstract]


def test_subclass_requires_test_method():
    class IncompleteConnector(BaseConnector):
        id = "incomplete"
        name = "Incomplete"
        kind = "sender"
        category = "notification"
        description = "no test method"
        version = "v0.1"
        status = "preview"
        icon_slug = "incomplete"

    with pytest.raises(TypeError):
        IncompleteConnector()  # type: ignore[abstract]


def test_complete_subclass_instantiates_and_exposes_metadata():
    class PingConnector(BaseConnector):
        id = "ping"
        name = "Ping"
        kind = "sender"
        category = "notification"
        description = "Ping connector"
        version = "v1.0"
        status = "stable"
        icon_slug = "ping"

        def test(self) -> TestResult:
            return TestResult(ok=True)

    connector = PingConnector()
    assert connector.id == "ping"
    assert connector.test().ok is True


from src.connectors.base import BaseSender, BaseIngester, BaseRunner


def test_sender_subclass_with_send_taking_payload_and_config():
    from src.connectors.base import SendResult

    class DummySender(BaseSender):
        id = "dummy"
        name = "Dummy"
        category = "notification"
        description = "Dummy sender"
        version = "v0.1"
        status = "preview"
        icon_slug = "dummy"

        def send(self, payload: dict, config: dict) -> SendResult:
            return SendResult(success=True, response_code=200)

        def test(self) -> TestResult:
            return TestResult(ok=True)

    sender = DummySender()
    assert sender.kind == "sender"
    result = sender.send({"msg": "hi"}, {"url": "https://example.com"})
    assert result.success is True
    assert result.response_code == 200


def test_ingester_subclass_with_verify_and_normalize():
    class DummyIngester(BaseIngester):
        id = "dummy-ingest"
        name = "Dummy ingester"
        category = "ci"
        description = "Dummy ingester"
        version = "v0.1"
        status = "preview"
        icon_slug = "dummy"

        def signature_header(self) -> str:
            return "X-Test-Signature"

        def verify_signature(self, body: bytes, header: str) -> bool:
            return header == "valid"

        def normalize(self, body: bytes) -> dict:
            return {"raw": body}

        def test(self) -> TestResult:
            return TestResult(ok=True)

    ing = DummyIngester()
    assert ing.kind == "ingester"
    assert ing.signature_header() == "X-Test-Signature"
    assert ing.verify_signature(b"x", "valid") is True
    assert ing.verify_signature(b"x", "bad") is False


def test_runner_subclass_is_metadata_only():
    class DummyRunner(BaseRunner):
        id = "dummy-runner"
        name = "Dummy runner"
        category = "runner"
        description = "Dummy runner"
        version = "v0.1"
        status = "preview"
        icon_slug = "dummy"

        def test(self) -> TestResult:
            return TestResult(ok=True)

    runner = DummyRunner()
    assert runner.kind == "runner"
    assert runner.test().ok is True


def test_wizard_subclass_is_metadata_only():
    from src.connectors.base import BaseWizard

    class DummyWizard(BaseWizard):
        id = "dummy-wizard"
        name = "Dummy wizard"
        category = "ci"
        description = "Dummy wizard"
        version = "v0.1"
        status = "preview"
        icon_slug = "dummy"

        def test(self) -> TestResult:
            return TestResult(ok=True)

    wizard = DummyWizard()
    assert wizard.kind == "wizard"
    assert wizard.test().ok is True
