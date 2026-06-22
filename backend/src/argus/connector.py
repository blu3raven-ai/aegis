"""ArgusConnector — client-side connector for the Argus intelligence service.

Argus is a closed-source, hosted/on-prem service (subscription). Aegis only
communicates with it over HTTPS using an API key. This module is the sole
integration point — never call Argus from anywhere else in Aegis.

Open-core boundary:
  - NullArgusConnector is returned when ARGUS_ENDPOINT / ARGUS_API_KEY are absent.
  - Every ArgusConnector method falls back to heuristics on network failure.
  - Data sent to Argus is metadata only — never source code, never secret values.

Data contract (spec §6 / Mode B):
  - Finding metadata: CVE ID, severity, package@version, file path, line
  - Repo / org identifiers
  - Chain context: finding IDs + edge types (NO contents)
  - Optional short SAST snippets (~5-10 lines), strippable via snippet_strip_level
"""
from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass, field
from typing import Any

import httpx

from src.argus.circuit_breaker import CircuitBreaker, CircuitOpenError
from src.argus.heuristics import (
    empty_rule_pack,
    heuristic_explain,
    heuristic_go_no_go,
    heuristic_score,
)
from src.argus.metrics import (
    argus_fallbacks_total,
    argus_request_duration_seconds,
    argus_requests_total,
    argus_retries_total,
    update_circuit_state_gauge,
)

logger = logging.getLogger(__name__)

# Default network timeout in milliseconds
_DEFAULT_TIMEOUT_MS = 2000

# Retry schedule (seconds between attempts). Index 0 = wait before attempt 2, etc.
_RETRY_BACKOFF_SECONDS = (0.1, 0.5, 2.0)

# Total wall-clock budget (seconds) for one method call including all retries.
_RETRY_BUDGET_SECONDS = 5.0

# Module-level pooled httpx client — created once, reused across all requests.
_pooled_client: httpx.Client | None = None


def _get_pooled_client() -> httpx.Client:
    global _pooled_client
    if _pooled_client is None:
        _pooled_client = httpx.Client(
            timeout=httpx.Timeout(10.0, connect=2.0),
            limits=httpx.Limits(max_connections=20, max_keepalive_connections=10),
            # retries=0 because we manage retry logic ourselves
            transport=httpx.HTTPTransport(retries=0),
        )
    return _pooled_client


@dataclass
class RiskScore:
    score: float           # 0-100
    source: str            # "argus" | "heuristic"
    rationale_id: str | None = None


@dataclass
class Decision:
    decision: str          # "allow" | "warn" | "block"
    blockers: list[str] = field(default_factory=list)
    rationale_id: str | None = None
    source: str = "heuristic"


@dataclass
class Explanation:
    markdown: str
    fix_suggestions: list[dict] = field(default_factory=list)
    source: str = "heuristic"


class ArgusConnector:
    """Real connector — makes HTTPS calls to the configured Argus endpoint.

    Falls back to heuristics on any network or HTTP error so Mode A (Argus
    unconfigured) and degraded Mode B (Argus temporarily unreachable) both
    produce valid results.

    Args:
        endpoint: Base URL of the Argus service (trailing slash optional).
        api_key:  Subscription API key for Bearer authentication.
        timeout_ms: Per-request timeout in milliseconds.
    """

    def __init__(self, endpoint: str, api_key: str, timeout_ms: int = _DEFAULT_TIMEOUT_MS) -> None:
        self._endpoint = endpoint.rstrip("/")
        self._api_key = api_key
        self._timeout = timeout_ms / 1000.0  # httpx uses seconds
        self._headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        self._circuit_breaker = CircuitBreaker(
            failure_threshold=5,
            recovery_timeout_seconds=30,
            half_open_max_calls=1,
            on_state_change=update_circuit_state_gauge,
        )

    # ── public API ────────────────────────────────────────────────────────────

    def score_finding(self, finding_metadata: dict) -> RiskScore:
        """Score a single finding using Argus intelligence.

        finding_metadata must contain only safe metadata fields — never raw
        source code or secret values. Required fields: cve_id, severity,
        package, version. Optional: file_path, line, epss_score.
        """
        payload = _safe_finding_payload(finding_metadata)
        endpoint_label = "/v1/score/finding"
        try:
            resp = self._call_with_retry(endpoint_label, "POST", payload)
            return RiskScore(
                score=float(resp["score"]),
                source="argus",
                rationale_id=resp.get("rationale_id"),
            )
        except CircuitOpenError:
            logger.warning(
                "argus.score_finding.circuit_open",
                extra={"endpoint": endpoint_label, "circuit_state": self._circuit_breaker.state.status},
            )
            argus_fallbacks_total.labels(reason="circuit_open").inc()
            return _heuristic_score_from_metadata(finding_metadata)
        except _ArgusTimeoutError as exc:
            logger.warning("argus.score_finding.timeout", extra={"endpoint": endpoint_label, "reason": str(exc)})
            argus_fallbacks_total.labels(reason="timeout").inc()
            return _heuristic_score_from_metadata(finding_metadata)
        except _ArgusNetworkError as exc:
            logger.warning("argus.score_finding.network_error", extra={"endpoint": endpoint_label, "reason": str(exc)})
            argus_fallbacks_total.labels(reason="network_error").inc()
            return _heuristic_score_from_metadata(finding_metadata)
        except _ArgusHttpError as exc:
            logger.warning(
                "argus.score_finding.http_error",
                extra={"endpoint": endpoint_label, "status_code": exc.status_code, "reason": str(exc)},
            )
            argus_fallbacks_total.labels(reason="http_error").inc()
            return _heuristic_score_from_metadata(finding_metadata)
        except _ArgusError as exc:
            logger.warning("argus.score_finding.error", extra={"endpoint": endpoint_label, "reason": str(exc)})
            argus_fallbacks_total.labels(reason="http_error").inc()
            return _heuristic_score_from_metadata(finding_metadata)

    def decide_go_no_go(
        self,
        service_id: str,
        findings_metadata: list[dict],
        policy_id: str | None = None,
    ) -> Decision:
        """Ask Argus for a gate decision (allow / warn / block) for a service.

        findings_metadata is a list of safe finding metadata dicts — same
        contract as score_finding's argument.
        """
        payload: dict[str, Any] = {
            "service_id": service_id,
            "findings": [_safe_finding_payload(f) for f in findings_metadata],
        }
        if policy_id:
            payload["policy_id"] = policy_id
        endpoint_label = "/v1/decide/go-no-go"
        try:
            resp = self._call_with_retry(endpoint_label, "POST", payload)
            return Decision(
                decision=resp["decision"],
                blockers=resp.get("blockers", []),
                rationale_id=resp.get("rationale_id"),
                source="argus",
            )
        except CircuitOpenError:
            logger.warning(
                "argus.decide_go_no_go.circuit_open",
                extra={"endpoint": endpoint_label, "circuit_state": self._circuit_breaker.state.status},
            )
            argus_fallbacks_total.labels(reason="circuit_open").inc()
            return _decision_from_heuristic(findings_metadata)
        except _ArgusTimeoutError as exc:
            logger.warning("argus.decide_go_no_go.timeout", extra={"endpoint": endpoint_label, "reason": str(exc)})
            argus_fallbacks_total.labels(reason="timeout").inc()
            return _decision_from_heuristic(findings_metadata)
        except _ArgusNetworkError as exc:
            logger.warning("argus.decide_go_no_go.network_error", extra={"endpoint": endpoint_label, "reason": str(exc)})
            argus_fallbacks_total.labels(reason="network_error").inc()
            return _decision_from_heuristic(findings_metadata)
        except _ArgusHttpError as exc:
            logger.warning(
                "argus.decide_go_no_go.http_error",
                extra={"endpoint": endpoint_label, "status_code": exc.status_code, "reason": str(exc)},
            )
            argus_fallbacks_total.labels(reason="http_error").inc()
            return _decision_from_heuristic(findings_metadata)
        except _ArgusError as exc:
            logger.warning("argus.decide_go_no_go.error", extra={"endpoint": endpoint_label, "reason": str(exc)})
            argus_fallbacks_total.labels(reason="http_error").inc()
            return _decision_from_heuristic(findings_metadata)

    def explain_chain(
        self,
        chain_metadata: dict,
        snippet_strip_level: str = "minimal",
    ) -> Explanation:
        """Request a rich markdown explanation and fix suggestions for a chain.

        chain_metadata must use _safe_chain_payload() to strip code contents.
        snippet_strip_level controls how much code context is sent:
          "none"    — no snippets
          "minimal" — up to 10 lines per snippet (default)
          "full"    — up to the limit Argus accepts
        """
        payload = _safe_chain_payload(chain_metadata, snippet_strip_level)
        endpoint_label = "/v1/explain/chain"
        try:
            resp = self._call_with_retry(endpoint_label, "POST", payload)
            return Explanation(
                markdown=resp.get("markdown", ""),
                fix_suggestions=resp.get("fix_suggestions", []),
                source="argus",
            )
        except CircuitOpenError:
            logger.warning(
                "argus.explain_chain.circuit_open",
                extra={"endpoint": endpoint_label, "circuit_state": self._circuit_breaker.state.status},
            )
            argus_fallbacks_total.labels(reason="circuit_open").inc()
            return Explanation(markdown=heuristic_explain(chain_metadata), fix_suggestions=[], source="heuristic")
        except (_ArgusTimeoutError, _ArgusNetworkError, _ArgusHttpError, _ArgusError) as exc:
            reason = _classify_error(exc)
            logger.warning("argus.explain_chain.failed", extra={"endpoint": endpoint_label, "reason": str(exc)})
            argus_fallbacks_total.labels(reason=reason).inc()
            return Explanation(markdown=heuristic_explain(chain_metadata), fix_suggestions=[], source="heuristic")

    def fetch_premium_rule_pack(self, since: str | None = None) -> dict:
        """Fetch premium correlation rules from Argus.

        Returns an empty dict when Argus is unreachable — built-in rules are
        unaffected.
        """
        params: dict[str, str] = {}
        if since:
            params["since"] = since
        endpoint_label = "/v1/rules/pack"
        try:
            return self._call_with_retry(endpoint_label, "GET", params=params)
        except CircuitOpenError:
            logger.warning(
                "argus.fetch_premium_rule_pack.circuit_open",
                extra={"endpoint": endpoint_label, "circuit_state": self._circuit_breaker.state.status},
            )
            argus_fallbacks_total.labels(reason="circuit_open").inc()
            return empty_rule_pack()
        except (_ArgusTimeoutError, _ArgusNetworkError, _ArgusHttpError, _ArgusError) as exc:
            reason = _classify_error(exc)
            logger.warning("argus.fetch_premium_rule_pack.failed", extra={"endpoint": endpoint_label, "reason": str(exc)})
            argus_fallbacks_total.labels(reason=reason).inc()
            return empty_rule_pack()

    def get_rule_packs(self) -> list[dict]:
        """Return a list of rule pack descriptors from Argus.

        Each descriptor is a dict with keys: pack_id, version, rule_classes.
        Returns an empty list when Argus is unreachable — built-in rules are
        unaffected.
        """
        endpoint_label = "/v1/rules/packs"
        try:
            resp = self._call_with_retry(endpoint_label, "GET")
            return resp.get("packs", [])
        except CircuitOpenError:
            logger.warning(
                "argus.get_rule_packs.circuit_open",
                extra={"endpoint": endpoint_label, "circuit_state": self._circuit_breaker.state.status},
            )
            argus_fallbacks_total.labels(reason="circuit_open").inc()
            return []
        except (_ArgusTimeoutError, _ArgusNetworkError, _ArgusHttpError, _ArgusError) as exc:
            reason = _classify_error(exc)
            logger.warning("argus.get_rule_packs.failed", extra={"endpoint": endpoint_label, "reason": str(exc)})
            argus_fallbacks_total.labels(reason=reason).inc()
            return []

    # ── internals ─────────────────────────────────────────────────────────────

    def _call_with_retry(
        self,
        path: str,
        method: str,
        body: dict | None = None,
        params: dict | None = None,
    ) -> dict:
        """Execute an HTTP call through the circuit breaker with retry on failure.

        Retries on 5xx and network errors only. 4xx responses are not retried
        because they indicate caller-side problems. Total wall-clock budget is
        capped at _RETRY_BUDGET_SECONDS.
        """
        budget_start = time.monotonic()
        last_exc: Exception | None = None
        max_attempts = len(_RETRY_BACKOFF_SECONDS) + 1

        for attempt in range(1, max_attempts + 1):
            if attempt > 1:
                backoff = _RETRY_BACKOFF_SECONDS[attempt - 2]
                elapsed = time.monotonic() - budget_start
                remaining = _RETRY_BUDGET_SECONDS - elapsed
                if remaining <= 0:
                    break
                actual_sleep = min(backoff, remaining)
                argus_retries_total.labels(endpoint=path).inc()
                logger.info(
                    "argus.retry",
                    extra={
                        "endpoint": path,
                        "attempt": attempt,
                        "backoff_seconds": actual_sleep,
                        "circuit_state": self._circuit_breaker.state.status,
                    },
                )
                time.sleep(actual_sleep)

            t0 = time.monotonic()
            try:
                if method == "POST":
                    result = self._circuit_breaker.call(self._post, path, body or {})
                else:
                    result = self._circuit_breaker.call(self._get, path, params)
                duration_ms = (time.monotonic() - t0) * 1000
                argus_requests_total.labels(endpoint=path, status="success").inc()
                argus_request_duration_seconds.labels(endpoint=path).observe(time.monotonic() - t0)
                logger.info(
                    "argus.request.success",
                    extra={
                        "endpoint": path,
                        "duration_ms": round(duration_ms, 1),
                        "attempt": attempt,
                        "circuit_state": self._circuit_breaker.state.status,
                    },
                )
                return result

            except CircuitOpenError:
                # Circuit is open — don't retry, propagate immediately for fallback
                raise

            except _ArgusHttpError as exc:
                duration_ms = (time.monotonic() - t0) * 1000
                argus_requests_total.labels(endpoint=path, status=f"http_{exc.status_code}").inc()
                argus_request_duration_seconds.labels(endpoint=path).observe(time.monotonic() - t0)
                logger.warning(
                    "argus.request.failed",
                    extra={
                        "endpoint": path,
                        "status_code": exc.status_code,
                        "duration_ms": round(duration_ms, 1),
                        "attempt": attempt,
                        "circuit_state": self._circuit_breaker.state.status,
                    },
                )
                # 4xx is a caller-side error; retrying won't help
                if exc.status_code < 500:
                    raise
                last_exc = exc

            except _ArgusNetworkError as exc:
                duration_ms = (time.monotonic() - t0) * 1000
                argus_requests_total.labels(endpoint=path, status="network_error").inc()
                logger.warning(
                    "argus.request.failed",
                    extra={
                        "endpoint": path,
                        "duration_ms": round(duration_ms, 1),
                        "attempt": attempt,
                        "circuit_state": self._circuit_breaker.state.status,
                        "reason": str(exc),
                    },
                )
                last_exc = exc

            except _ArgusTimeoutError as exc:
                duration_ms = (time.monotonic() - t0) * 1000
                argus_requests_total.labels(endpoint=path, status="timeout").inc()
                logger.warning(
                    "argus.request.failed",
                    extra={
                        "endpoint": path,
                        "duration_ms": round(duration_ms, 1),
                        "attempt": attempt,
                        "circuit_state": self._circuit_breaker.state.status,
                        "reason": "timeout",
                    },
                )
                last_exc = exc

            except _ArgusError as exc:
                # Catch-all for the base class — covers hand-crafted test mocks and
                # any future subclasses not yet enumerated above.
                duration_ms = (time.monotonic() - t0) * 1000
                argus_requests_total.labels(endpoint=path, status="error").inc()
                logger.warning(
                    "argus.request.failed",
                    extra={
                        "endpoint": path,
                        "duration_ms": round(duration_ms, 1),
                        "attempt": attempt,
                        "circuit_state": self._circuit_breaker.state.status,
                        "reason": str(exc),
                    },
                )
                last_exc = exc

        # All attempts exhausted — propagate the last error
        assert last_exc is not None
        raise last_exc

    def _post(self, path: str, body: dict) -> dict:
        url = f"{self._endpoint}{path}"
        try:
            client = _get_pooled_client()
            resp = client.post(url, json=body, headers=self._headers)
            resp.raise_for_status()
            return resp.json()
        except httpx.TimeoutException as exc:
            raise _ArgusTimeoutError(f"Timeout calling {url}") from exc
        except httpx.HTTPStatusError as exc:
            raise _ArgusHttpError(
                f"HTTP {exc.response.status_code} from {url}",
                status_code=exc.response.status_code,
            ) from exc
        except httpx.RequestError as exc:
            raise _ArgusNetworkError(f"Network error calling {url}: {exc}") from exc

    def _get(self, path: str, params: dict | None = None) -> dict:
        url = f"{self._endpoint}{path}"
        try:
            client = _get_pooled_client()
            resp = client.get(url, params=params, headers=self._headers)
            resp.raise_for_status()
            return resp.json()
        except httpx.TimeoutException as exc:
            raise _ArgusTimeoutError(f"Timeout calling {url}") from exc
        except httpx.HTTPStatusError as exc:
            raise _ArgusHttpError(
                f"HTTP {exc.response.status_code} from {url}",
                status_code=exc.response.status_code,
            ) from exc
        except httpx.RequestError as exc:
            raise _ArgusNetworkError(f"Network error calling {url}: {exc}") from exc


class NullArgusConnector(ArgusConnector):
    """Always returns heuristic fallbacks. Used when Argus is unconfigured.

    No network calls are made. This is the default in Mode A (open-source,
    no Argus subscription).
    """

    def __init__(self) -> None:
        pass  # skip endpoint/key validation

    def score_finding(self, finding_metadata: dict) -> RiskScore:
        argus_fallbacks_total.labels(reason="unconfigured").inc()
        return _heuristic_score_from_metadata(finding_metadata)

    def decide_go_no_go(
        self,
        service_id: str,
        findings_metadata: list[dict],
        policy_id: str | None = None,
    ) -> Decision:
        argus_fallbacks_total.labels(reason="unconfigured").inc()
        return _decision_from_heuristic(findings_metadata)

    def explain_chain(
        self,
        chain_metadata: dict,
        snippet_strip_level: str = "minimal",
    ) -> Explanation:
        argus_fallbacks_total.labels(reason="unconfigured").inc()
        return Explanation(
            markdown=heuristic_explain(chain_metadata),
            fix_suggestions=[],
            source="heuristic",
        )

    def fetch_premium_rule_pack(self, since: str | None = None) -> dict:
        argus_fallbacks_total.labels(reason="unconfigured").inc()
        return empty_rule_pack()

    def get_rule_packs(self) -> list[dict]:
        return []



def get_argus_connector() -> ArgusConnector:
    """Return a real ArgusConnector if env is configured, else NullArgusConnector."""
    endpoint = os.getenv("ARGUS_ENDPOINT")
    api_key = os.getenv("ARGUS_API_KEY")
    if endpoint and api_key:
        return ArgusConnector(endpoint, api_key)
    return NullArgusConnector()



class _ArgusError(Exception):
    """Base class for Argus connector errors."""


class _ArgusHttpError(_ArgusError):
    """An HTTP response with a non-2xx status code was received."""

    def __init__(self, message: str, status_code: int) -> None:
        super().__init__(message)
        self.status_code = status_code


class _ArgusNetworkError(_ArgusError):
    """A network-level failure (DNS, connection refused, etc.)."""


class _ArgusTimeoutError(_ArgusError):
    """The remote call exceeded the configured timeout."""


def _classify_error(exc: Exception) -> str:
    """Map an error to a fallback reason label for metrics."""
    if isinstance(exc, _ArgusTimeoutError):
        return "timeout"
    if isinstance(exc, _ArgusNetworkError):
        return "network_error"
    return "http_error"


def _safe_finding_payload(finding: dict) -> dict:
    """Build a metadata-only payload safe to send to Argus.

    Allowlist approach: only named fields are included. This prevents
    accidentally serialising secret values, source code blobs, or internal
    DB IDs that must not leave Aegis.
    """
    return {
        k: finding[k]
        for k in (
            "cve_id", "severity", "package", "version",
            "file_path", "line", "epss_score", "purl",
            "org", "repo", "identity_key",
        )
        if k in finding
    }


def _safe_chain_payload(chain: dict, snippet_strip_level: str) -> dict:
    """Build a metadata-only chain payload for explain_chain.

    Strips code contents according to snippet_strip_level. Edge types are
    included; edge contents (code diffs, etc.) are never sent.
    """
    safe: dict[str, Any] = {
        "chain_id": chain.get("chain_id"),
        "chain_type": chain.get("chain_type"),
        "snippet_strip_level": snippet_strip_level,
        "findings": [
            _safe_finding_payload(f) for f in chain.get("findings", [])
        ],
        "edges": [
            {"from_id": e.get("from_id"), "to_id": e.get("to_id"), "edge_type": e.get("edge_type")}
            for e in chain.get("edges", [])
        ],
    }
    # Include short SAST snippets only when caller explicitly requests them
    if snippet_strip_level != "none" and chain.get("snippets"):
        _SNIPPET_LINE_LIMITS = {"minimal": 10, "full": 50}
        limit = _SNIPPET_LINE_LIMITS.get(snippet_strip_level, 10)
        safe["snippets"] = [
            {
                "finding_id": s.get("finding_id"),
                "lines": (s.get("lines") or [])[:limit],
            }
            for s in chain.get("snippets", [])
        ]
    return safe


def _heuristic_score_from_metadata(finding: dict) -> RiskScore:
    """Compute a heuristic RiskScore from finding metadata fields."""
    severity = finding.get("severity", "medium")
    epss = float(finding.get("epss_score", 0.0))
    reachability_bonus = 5.0 if finding.get("reachable") else 0.0
    chain_bonus = 5.0 if finding.get("in_chain") else 0.0
    score = heuristic_score(severity, epss, reachability_bonus, chain_bonus)
    return RiskScore(score=score, source="heuristic", rationale_id=None)


def _decision_from_heuristic(findings_metadata: list[dict]) -> Decision:
    """Build a Decision dataclass from heuristic_go_no_go output.

    heuristic_go_no_go returns a plain dict with a human-readable 'rationale'
    key; Decision uses 'rationale_id' (an opaque reference). We map between
    them here so the heuristics module stays schema-free.
    """
    result = heuristic_go_no_go(findings_metadata)
    return Decision(
        decision=result["decision"],
        blockers=result.get("blockers", []),
        rationale_id=None,  # heuristics produce no opaque rationale ID
        source="heuristic",
    )
