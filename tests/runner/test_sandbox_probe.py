"""Benign probe generation from a runtime_question."""
from __future__ import annotations

import json
from unittest.mock import MagicMock

from runner.sandbox.probe import ProbeSpec, generate_probe
from runner.verification.llm_client import LlmResponse


def _make_resp(content: str) -> LlmResponse:
    return LlmResponse(content=content, tokens_in=10, tokens_out=20, prompt_hash="x")


def _mock_llm(*responses: str) -> MagicMock:
    from runner.verification.llm_client import LlmClient

    llm = MagicMock()
    llm.chat.side_effect = [_make_resp(r) for r in responses]
    llm.chat_json.side_effect = lambda *a, **kw: LlmClient.chat_json(llm, *a, **kw)
    return llm


_SPEC = json.dumps({
    "port": 8080,
    "requests": [{"method": "GET", "path": "/admin", "headers": {}, "authenticated": False}],
    "flaw_signal": "any 2xx to /admin without a credential",
    "control_signal": "401 or 403 without a credential",
})


def test_generates_a_probe_spec():
    spec = generate_probe("Confirm /admin is reachable without auth", llm=_mock_llm(_SPEC), port_hint=8080)
    assert isinstance(spec, ProbeSpec)
    assert spec.port == 8080
    assert spec.requests[0].path == "/admin"
    assert spec.requests[0].authenticated is False
    assert "2xx" in spec.flaw_signal


def test_none_without_llm():
    assert generate_probe("anything", llm=None) is None


def test_none_for_empty_question():
    assert generate_probe("   ", llm=_mock_llm(_SPEC)) is None


def test_none_when_no_requests():
    empty = json.dumps({"port": 0, "requests": [], "flaw_signal": "", "control_signal": ""})
    assert generate_probe("q", llm=_mock_llm(empty)) is None


def test_prompt_is_benign_locked():
    from runner.sandbox import probe
    sys = probe._PROBE_SYSTEM.lower()
    assert "read-only" in sys or "observe" in sys
    assert "must not" in sys and "exfiltrate" in sys and "destructive" in sys


def test_context_is_injected_into_prompt():
    # The probe generator must receive the finding's location, exploit chain,
    # and flagged code so it targets the real endpoint instead of guessing.
    llm = _mock_llm(_SPEC)
    generate_probe(
        "Confirm /admin is reachable without auth",
        llm=llm,
        port_hint=8080,
        context={
            "file": "app/routes/admin.py",
            "exploit_chain": "unauthenticated GET /admin returns the dashboard",
            "code_window": "@app.get('/admin')\ndef admin(): return render()",
        },
    )
    user_msg = llm.chat.call_args_list[0].args[0][1]["content"]
    assert "app/routes/admin.py" in user_msg
    assert "unauthenticated GET /admin" in user_msg
    assert "@app.get('/admin')" in user_msg


def test_context_optional_backwards_compatible():
    # Without context the prompt is still valid (just the question + port hint).
    spec = generate_probe("Confirm /admin is reachable", llm=_mock_llm(_SPEC), port_hint=8080)
    assert isinstance(spec, ProbeSpec)
