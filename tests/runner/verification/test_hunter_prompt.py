"""Hunter prompt construction — the reachability signal and call chain must
reach the model, not be silently dropped."""
from __future__ import annotations

from runner.verification.prompts.sast import hunter_user_message


def _finding():
    return {
        "tool": "code_scanning",
        "rule": "py.command-injection",
        "severity": "high",
        "file": "app/exec.py",
        "line": 12,
    }


def test_reachability_verdict_is_included():
    msg = hunter_user_message(
        _finding(), "// code", {"verdict": "unreachable", "reason": "no entry point calls this"}
    )
    assert "Reachability: unreachable" in msg


def test_call_chain_hops_are_rendered():
    chain = [
        {"function": "handle_request", "file": "app/server.py", "line": 40, "snippet": "def handle_request(req):"},
        {"function": "exec_cmd", "file": "app/exec.py", "line": 9, "snippet": "def exec_cmd(cmd): os.system(cmd)"},
    ]
    msg = hunter_user_message(
        _finding(), "// code", {"verdict": "reachable", "entry_point": "handle_request", "call_chain": chain}
    )
    assert "Call chain (entry point to finding):" in msg
    # Hops are numbered and carry the function + file:line + first snippet line.
    assert "[1] handle_request (app/server.py:40)" in msg
    assert "[2] exec_cmd (app/exec.py:9)" in msg
    assert "def handle_request(req):" in msg


def test_call_chain_capped_at_eight_hops():
    chain = [
        {"function": f"fn{i}", "file": f"f{i}.py", "line": i, "snippet": f"line {i}"}
        for i in range(20)
    ]
    msg = hunter_user_message(
        _finding(), "// code", {"verdict": "reachable", "call_chain": chain}
    )
    assert "[8] fn7" in msg
    assert "fn8" not in msg


def test_no_call_chain_section_when_absent():
    msg = hunter_user_message(_finding(), "// code", {"verdict": "reachable", "entry_point": "module-level"})
    assert "Call chain" not in msg
    assert "Reachability: reachable" in msg
