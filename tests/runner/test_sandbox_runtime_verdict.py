"""The resolver must only flip a verdict on an unambiguous no-credential signal.
Every ambiguous or failed probe must leave the finding at needs_runtime_verification
— a false confirmed/ruled_out is worse than an unresolved finding."""
from __future__ import annotations

from runner.sandbox.probe import ProbeRequest
from runner.sandbox.probe_runner import ProbeResult
from runner.sandbox.runtime_verdict import resolve_runtime_verdict


def _r(status, *, authed=False, method="GET", path="/admin"):
    return ProbeResult(ProbeRequest(method=method, path=path, authenticated=authed), status=status)


def test_unauth_2xx_confirms():
    res = resolve_runtime_verdict([_r(200)])
    assert res.verdict == "confirmed"
    assert res.evidence["kind"] == "runtime_log" and "without authentication" in res.evidence["snippet"]


def test_unauth_403_rules_out():
    res = resolve_runtime_verdict([_r(403)])
    assert res.verdict == "ruled_out" and "enforced" in res.evidence["snippet"]


def test_unauth_401_rules_out():
    assert resolve_runtime_verdict([_r(401)]).verdict == "ruled_out"


def test_redirect_is_inconclusive():
    # A 302 is often a protective redirect to /login — never treat it as exposure.
    res = resolve_runtime_verdict([_r(302)])
    assert res.verdict == "needs_runtime_verification" and res.evidence is None


def test_404_is_inconclusive():
    assert resolve_runtime_verdict([_r(404)]).verdict == "needs_runtime_verification"


def test_transport_failure_is_inconclusive():
    # status 0 = no HTTP response; must never resolve.
    assert resolve_runtime_verdict([_r(0)]).verdict == "needs_runtime_verification"


def test_no_unauth_request_is_inconclusive():
    # Only an authenticated baseline ran — nothing to say about exposure.
    assert resolve_runtime_verdict([_r(200, authed=True)]).verdict == "needs_runtime_verification"


def test_any_unauth_2xx_wins_over_a_rejected_sibling():
    res = resolve_runtime_verdict([_r(403, path="/a"), _r(200, path="/b")])
    assert res.verdict == "confirmed"


def test_mixed_rejections_without_2xx_are_inconclusive():
    # 403 + 500 → not all rejections → inconclusive, not ruled_out.
    assert resolve_runtime_verdict([_r(403), _r(500)]).verdict == "needs_runtime_verification"
