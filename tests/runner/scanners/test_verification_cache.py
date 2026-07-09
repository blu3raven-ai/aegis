"""Verification cache: a finding already verified with identical input replays
its verdict from the backend instead of re-spending LLM tokens."""
from __future__ import annotations

from runner.scanners.code_scanning import scanner as sc
from runner.verification.cache import verification_input_hash
from runner.scanners._shared import JobEnv


def _finding(**over):
    f = {"rule_id": "r1", "file_path": "a.py", "start_line": 5,
         "code_window": "token = 1", "severity": "high"}
    f.update(over)
    return f


def test_hash_stable_and_content_sensitive():
    base = _finding()
    assert verification_input_hash(base) == verification_input_hash(_finding())
    # Changed code → different key (must re-verify).
    assert verification_input_hash(base) != verification_input_hash(_finding(code_window="token = 2"))
    # Changed reachability → different key.
    assert verification_input_hash(base) != verification_input_hash(_finding(reachability="reachable"))


class _FakeBackend:
    def __init__(self, results):
        self._results = results
        self.calls = 0

    def verification_cache_lookup(self, *, tool, hashes):
        self.calls += 1
        return self._results


def test_cache_hit_replays_verdict_without_calling_the_llm(monkeypatch):
    finding = _finding()
    h = verification_input_hash(finding)
    backend = _FakeBackend({
        h: {"verdict": "ruled_out", "evidence": [], "exploit_chain": "chain",
            "verification_metadata": {"model": "m", "tokens_in": 999, "tokens_out": 999}},
    })
    # verify_finding must NOT be called on a cache hit.
    called = {"n": 0}
    monkeypatch.setattr(sc, "verify_finding", lambda **kw: called.__setitem__("n", called["n"] + 1))

    out = sc._maybe_verify(
        findings=[finding], repo_root="/tmp", llm=object(),
        scan_budget=sc._build_scan_budget(JobEnv({})), backend=backend,
    )

    assert called["n"] == 0
    assert backend.calls == 1
    meta = out[0]["verification_metadata"]
    assert out[0]["verdict"] == "ruled_out"
    assert out[0]["exploit_chain"] == "chain"
    assert meta["cache_hit"] is True
    # Tokens zeroed so a replayed verdict isn't counted as fresh spend.
    assert meta["tokens_in"] == 0 and meta["tokens_out"] == 0
    assert meta["verification_input_hash"] == h


def test_cache_miss_verifies_and_stamps_the_hash(monkeypatch):
    finding = _finding()
    h = verification_input_hash(finding)
    backend = _FakeBackend({})  # empty cache → miss

    class _Result:
        verdict = "confirmed"
        evidence = []
        exploit_chain = ""
        tokens_in = 10
        tokens_out = 20
        verification_metadata = {"model": "m", "tokens_in": 10, "tokens_out": 20}

    monkeypatch.setattr(sc, "verify_finding", lambda **kw: _Result())

    out = sc._maybe_verify(
        findings=[finding], repo_root="/tmp", llm=object(),
        scan_budget=sc._build_scan_budget(JobEnv({})), backend=backend,
    )

    meta = out[0]["verification_metadata"]
    assert out[0]["verdict"] == "confirmed"
    assert meta.get("cache_hit") is None
    # The key is stamped so the next scan can cache-hit this exact input.
    assert meta["verification_input_hash"] == h
