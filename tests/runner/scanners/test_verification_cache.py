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


def test_parallel_verify_preserves_per_finding_order(monkeypatch):
    # With concurrent workers, each result must land on its own finding — a slot
    # mix-up would attach the wrong verdict/evidence to a finding.
    findings = [_finding(rule_id=f"r{i}", code_window=f"w{i}", severity="high") for i in range(6)]

    class _R:
        def __init__(self, rule_id):
            self.verdict = f"verdict-{rule_id}"
            self.evidence = [{"rule": rule_id}]
            self.exploit_chain = f"chain-{rule_id}"
            self.tokens_in = 1
            self.tokens_out = 1
            self.verification_metadata = {}

    monkeypatch.setattr(sc, "verify_finding", lambda *, finding, **kw: _R(finding["rule_id"]))

    out = sc._maybe_verify(
        findings=findings, repo_root="/tmp", llm=object(),
        scan_budget=sc._build_scan_budget(JobEnv({})), backend=None, max_workers=4,
    )

    assert len(out) == 6
    for i, f in enumerate(out):
        assert f["verdict"] == f"verdict-r{i}", f"finding {i} got the wrong result"
        assert f["exploit_chain"] == f"chain-r{i}"
