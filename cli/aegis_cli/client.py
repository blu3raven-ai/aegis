"""HTTP client wrapping the Aegis backend REST API.

All requests carry a Bearer token.  The client is intentionally thin —
it maps method calls to HTTP verbs and returns parsed JSON dicts/lists.
Error handling is surfaced as AegisAPIError so callers can catch one
exception type regardless of which endpoint failed.

Backend endpoint prefixes (verified against router.py files):
  - dependencies:        /dependencies/api
  - code scanning (SAST): /code-scanning/api
  - secrets:             /secrets/api
  - container scanning:  /container-scanning/api

The go/no-go decision endpoint from spec §6.1 is not yet implemented in the
backend.  get_decision() falls back to a local heuristic using findings data.
"""

from __future__ import annotations

from typing import Any

import httpx

# Scanner types the backend accepts, keyed by CLI alias.
SCANNER_ENDPOINT_MAP: dict[str, str] = {
    "dependencies": "/dependencies/api",
    "code_scanning": "/code-scanning/api",
    "sast": "/code-scanning/api",
    "secrets": "/secrets/api",
    "containers": "/container-scanning/api",
    "container_scanning": "/container-scanning/api",
}

# Severities the backend returns (dependencies uses security_advisory.severity).
SEVERITY_LEVELS = ["critical", "high", "medium", "low"]


class AegisAPIError(Exception):
    """Raised when the backend returns an HTTP error or an unexpected payload."""

    def __init__(self, message: str, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code


class AegisClient:
    def __init__(
        self,
        base_url: str,
        api_token: str,
        timeout: float = 30.0,
    ) -> None:
        self._base = base_url.rstrip("/")
        self._timeout = timeout
        self._http = httpx.Client(
            headers={"Authorization": f"Bearer {api_token}"},
            timeout=timeout,
        )

    # ------------------------------------------------------------------
    # Scan triggers
    # ------------------------------------------------------------------

    def trigger_scan(
        self,
        *,
        org: str,
        scanner_type: str = "dependencies",
        repo: str | None = None,
    ) -> dict[str, Any]:
        """Trigger a scan for an org.

        Returns the raw backend payload: {"runs": [...], "message": "..."}.
        The backend queues all repos for the org; per-repo filtering is not
        yet exposed via the HTTP API.
        """
        prefix = self._scanner_prefix(scanner_type)
        url = f"{self._base}{prefix}/runs"

        params: dict[str, str] = {}
        # org is sent as a query param; the backend's require_orgs dependency
        # reads ?org=<name> from the request.
        params["org"] = org
        if repo:
            # Hint only — backend currently scans all repos for the org.
            params["repo"] = repo

        resp = self._http.post(url, params=params)
        return self._parse(resp)

    # ------------------------------------------------------------------
    # Scan status
    # ------------------------------------------------------------------

    def get_scan_status(self, scan_id: str, *, org: str) -> dict[str, Any]:
        """Get the status of a scan run.

        The backend exposes run state via the history endpoint.  We search
        for the matching run_id across all recent runs.

        Returns {id, org, status, progress, findingsCount, ...}.
        Raises AegisAPIError with status_code=404 when not found.
        """
        # Try each scanner type since we may not know which one ran.
        for prefix in SCANNER_ENDPOINT_MAP.values():
            seen: set[str] = set()
            if prefix in seen:
                continue
            seen.add(prefix)
            try:
                url = f"{self._base}{prefix}/history"
                resp = self._http.get(url, params={"org": org})
                data = self._parse(resp)
                for run in data.get("history", []):
                    if run.get("id") == scan_id:
                        return run
            except AegisAPIError:
                continue

        raise AegisAPIError(f"Scan '{scan_id}' not found", status_code=404)

    def get_latest_run(
        self, *, org: str, scanner_type: str = "dependencies"
    ) -> dict[str, Any]:
        """Return {latest, lastCompleted} for the given scanner."""
        prefix = self._scanner_prefix(scanner_type)
        url = f"{self._base}{prefix}/runs/latest"
        resp = self._http.get(url, params={"org": org})
        return self._parse(resp)

    # ------------------------------------------------------------------
    # Findings
    # ------------------------------------------------------------------

    def iter_all_findings(
        self,
        *,
        org: str,
        severity: list[str] | None = None,
        scanner: list[str] | None = None,
        state: list[str] | None = None,
        page_limit: int = 200,
        max_findings: int = 10_000,
    ) -> list[dict[str, Any]]:
        """Walk every cursor page of /api/v1/findings and return the merged list.

        Reports, PR comments, and bulk triage all need the full match set, so
        cursor pagination is unrolled here. *max_findings* is a defensive hard
        ceiling against a non-terminating server cursor; the result is sliced
        to that bound so callers cannot accidentally process more than the
        guard allows.
        """
        collected: list[dict[str, Any]] = []
        cursor: str | None = None
        while True:
            page = self.list_findings(
                org=org,
                severity=severity,
                scanner=scanner,
                state=state,
                limit=page_limit,
                cursor=cursor,
            )
            collected.extend(page.get("findings") or [])
            cursor = page.get("next_cursor")
            if not cursor or len(collected) >= max_findings:
                return collected[:max_findings]

    def list_findings(
        self,
        *,
        org: str,
        severity: list[str] | None = None,
        scanner: list[str] | None = None,
        state: list[str] | None = None,
        q: str | None = None,
        cve: str | None = None,
        sort: str | None = None,
        direction: str | None = None,
        limit: int | None = None,
        cursor: str | None = None,
    ) -> dict[str, Any]:
        """Return aggregated findings via GET /api/v1/findings.

        Single backend call — server-side aggregates across all four scanners.
        Returns the raw envelope ``{findings, next_cursor, total_count}`` so
        callers can drive cursor pagination.

        Scanner names are translated from the CLI vocabulary (``dependencies``,
        ``code_scanning``/``sast``, ``secrets``, ``containers``/
        ``container_scanning``) to the public shorthand the endpoint expects
        (``deps``, ``sast``, ``secrets``, ``container``).
        """
        params: dict[str, Any] = {"org_id": org}
        if severity:
            params["severity"] = ",".join(severity)
        if scanner:
            params["scanner"] = ",".join(_to_public_scanner(s) for s in scanner)
        if state:
            params["state"] = ",".join(state)
        if q:
            params["q"] = q
        if cve:
            params["cve"] = cve
        if sort:
            params["sort"] = sort
        if direction:
            params["direction"] = direction
        if limit is not None:
            params["limit"] = limit
        if cursor:
            params["cursor"] = cursor

        url = f"{self._base}/api/v1/findings"
        resp = self._http.get(url, params=params)
        data = self._parse(resp)
        if not isinstance(data, dict):
            raise AegisAPIError("Unexpected /api/v1/findings response shape")
        return data

    def get_findings(
        self,
        *,
        org: str,
        repo: str | None = None,
        severity: list[str] | None = None,
        scanner: list[str] | None = None,
    ) -> list[dict[str, Any]]:
        """Return open findings for an org.

        Findings come from the history endpoint's embedded run data or, for
        dependencies, from the snapshot.  We aggregate across scanner types
        requested (default: all) and apply client-side filters because the
        backend doesn't expose a unified /findings GET endpoint yet.

        Severity filter values match backend: critical, high, medium, low.
        Scanner filter values: dependencies, code_scanning, secrets, containers.
        """
        scanner_types = scanner or list(SCANNER_ENDPOINT_MAP.keys())
        # De-duplicate aliased keys
        prefixes: dict[str, str] = {}
        for s in scanner_types:
            p = SCANNER_ENDPOINT_MAP.get(s.lower())
            if p and p not in prefixes:
                prefixes[s] = p

        all_findings: list[dict[str, Any]] = []

        for scanner_name, prefix in prefixes.items():
            try:
                raw = self._fetch_findings_for_scanner(
                    prefix=prefix, org=org, scanner_name=scanner_name
                )
                all_findings.extend(raw)
            except AegisAPIError:
                # A scanner with no data yet returns empty; keep going.
                continue

        # Client-side filters
        if severity:
            low_sev = {s.lower() for s in severity}
            all_findings = [
                f for f in all_findings
                if _extract_severity(f).lower() in low_sev
            ]

        if repo:
            all_findings = [
                f for f in all_findings
                if repo in (f.get("repository", {}).get("full_name", "")
                            or f.get("repo", ""))
            ]

        return all_findings

    def _fetch_findings_for_scanner(
        self, *, prefix: str, org: str, scanner_name: str
    ) -> list[dict[str, Any]]:
        """Fetch findings from the history endpoint for one scanner type.

        The backend stores findings in the latest completed run's embedded
        data.  We read the history and return findings tagged with the scanner.
        """
        url = f"{self._base}{prefix}/history"
        resp = self._http.get(url, params={"org": org})
        data = self._parse(resp)

        findings: list[dict[str, Any]] = []
        for run in data.get("history", []):
            if run.get("status") not in ("completed", "completed_with_merge_error"):
                continue
            for alert in run.get("alerts", []):
                alert["_scanner"] = scanner_name
                findings.append(alert)
            # dependencies scanner nests counts not alerts in history runs;
            # the full alert list lives in the snapshot endpoint
            break  # latest completed run only

        # If no embedded alerts and this is dependencies, fetch snapshot.
        if not findings and "dependencies" in prefix:
            findings = self._fetch_dependencies_snapshot(org=org)
            for f in findings:
                f["_scanner"] = "dependencies"

        return findings

    def _fetch_dependencies_snapshot(self, *, org: str) -> list[dict[str, Any]]:
        """Read the full dependencies alert list from the history endpoint.

        The backend exposes aggregate counts in history runs but not the
        individual alerts.  The snapshot is obtained via /runs/latest which
        returns summary data.  For now we return what's available.
        """
        # The backend does not expose a standalone /findings GET for dependencies.
        # The alert objects are served to the frontend via the GraphQL layer or
        # via a direct DB read.  We surface what the REST API provides.
        return []

    # ------------------------------------------------------------------
    # Finding explanation (Argus AI — stub until endpoint is live)
    # ------------------------------------------------------------------

    def get_explanation(self, *, finding_id: str) -> dict[str, Any]:
        """Return an AI explanation for a finding.

        Attempts the Argus explanation endpoint.  Falls back to a stub
        response when the endpoint is not yet implemented — callers can
        check `source` to distinguish the two cases.
        """
        url = f"{self._base}/api/v1/findings/{finding_id}/explain"
        try:
            resp = self._http.get(url)
            if resp.status_code not in (404, 405):
                return self._parse(resp)
        except (httpx.RequestError, AegisAPIError):
            pass

        return {
            "finding_id": finding_id,
            "markdown": (
                f"Explanation for finding `{finding_id}` is not yet available. "
                "Connect Argus to enable AI-powered explanations and fix suggestions."
            ),
            "fix_suggestions": [],
            "source": "stub",
        }

    # ------------------------------------------------------------------
    # CVE / dependency lookups (stub until endpoint is live)
    # ------------------------------------------------------------------

    def lookup_cve(self, *, cve_id: str) -> dict[str, Any]:
        """Return CVE details including EPSS and exploit availability.

        Attempts the backend intel endpoint.  Falls back to a stub when
        the endpoint is absent.
        """
        url = f"{self._base}/api/v1/intel/cve/{cve_id}"
        try:
            resp = self._http.get(url)
            if resp.status_code not in (404, 405):
                return self._parse(resp)
        except (httpx.RequestError, AegisAPIError):
            pass

        return {
            "cve_id": cve_id,
            "cve_info": None,
            "epss": None,
            "exploit_availability": None,
            "source": "stub",
            "note": (
                "CVE lookup endpoint not yet implemented. "
                "Connect Argus for live EPSS and exploit data."
            ),
        }

    def check_dependency(
        self, *, package_name: str, version: str
    ) -> dict[str, Any]:
        """Check whether a package version is vulnerable.

        Attempts the backend advisory endpoint.  Falls back to a stub
        when the endpoint is absent.
        """
        url = f"{self._base}/api/v1/advisories/check"
        params = {"package": package_name, "version": version}
        try:
            resp = self._http.get(url, params=params)
            if resp.status_code not in (404, 405):
                return self._parse(resp)
        except (httpx.RequestError, AegisAPIError):
            pass

        return {
            "package_name": package_name,
            "version": version,
            "vulnerable": None,
            "advisories": [],
            "source": "stub",
            "note": (
                "Dependency advisory endpoint not yet implemented. "
                "Run a scan to check this package against the Aegis database."
            ),
        }

    # ------------------------------------------------------------------
    # SBOM
    # ------------------------------------------------------------------

    def get_sbom(self, *, org: str, repo: str) -> dict[str, Any]:
        """Return the current SBOM for a repository."""
        url = f"{self._base}/dependencies/api/sbom"
        resp = self._http.get(url, params={"org": org, "repo": repo})
        return self._parse(resp)

    def export_sbom(
        self,
        *,
        repo: str | None = None,
        image_digest: str | None = None,
        format: str = "cyclonedx-json",
    ) -> str:
        """Return the serialised SBOM content in the requested format.

        Exactly one of *repo* or *image_digest* must be provided.
        *format* must be one of: cyclonedx-json, cyclonedx-xml, spdx-json,
        spdx-tag-value.

        The backend returns the raw SBOM text (not a JSON wrapper) for
        non-JSON formats; for cyclonedx-json and spdx-json the response body
        is the serialised document itself.
        """
        if repo is None and image_digest is None:
            raise ValueError("Exactly one of 'repo' or 'image_digest' must be provided.")
        if repo is not None and image_digest is not None:
            raise ValueError("Provide either 'repo' or 'image_digest', not both.")

        if repo is not None:
            url = f"{self._base}/api/v1/sboms/repo/{repo}"
        else:
            url = f"{self._base}/api/v1/sboms/image/{image_digest}"

        resp = self._http.get(url, params={"format": format})
        if resp.status_code >= 400:
            try:
                detail = resp.json().get("detail") or resp.text
            except Exception:
                detail = resp.text
            raise AegisAPIError(detail, status_code=resp.status_code)

        # Return the raw text so callers can write it to a file without
        # an extra JSON parse/serialise round-trip.
        return resp.text

    def list_sbom_history(self, repo: str) -> list[dict]:
        """Return historical SBOM versions for a repository.

        Each entry contains: manifest_set_hash, created_at, blob_pointer,
        content_hash, tool_version.
        """
        url = f"{self._base}/api/v1/sboms/repo/{repo}/history"
        resp = self._http.get(url)
        result = self._parse(resp)
        # Backend always returns a list; add a guard for unexpected shapes.
        if not isinstance(result, list):
            return []
        return result

    def diff_sbom(
        self,
        *,
        repo_id: str,
        from_hash: str,
        to_hash: str,
    ) -> dict[str, Any]:
        """Return the component-level diff between two cached SBOMs.

        Result keys: added, removed, version_changed, unchanged_count.
        """
        url = f"{self._base}/api/v1/sboms/diff"
        resp = self._http.get(
            url,
            params={"repo_id": repo_id, "from_hash": from_hash, "to_hash": to_hash},
        )
        return self._parse(resp)

    # ------------------------------------------------------------------
    # Finding lifecycle (triage)
    # ------------------------------------------------------------------

    def dismiss_finding(self, finding_id: str, *, reason: str) -> dict[str, Any]:
        """Dismiss a finding by ID.

        POSTs to the lifecycle endpoint with state=dismissed.  Raises
        NotImplementedError with a helpful message when the backend endpoint
        does not exist yet so CLI callers can fail loudly.
        """
        url = f"{self._base}/api/v1/findings/{finding_id}/lifecycle"
        payload = {"state": "dismissed", "reason": reason}
        try:
            resp = self._http.post(url, json=payload)
            if resp.status_code not in (404, 405):
                return self._parse(resp)
        except (httpx.RequestError, AegisAPIError):
            raise

        raise NotImplementedError(
            f"Finding lifecycle endpoint not yet implemented for finding '{finding_id}'. "
            "Upgrade the Aegis backend to enable bulk triage operations."
        )

    def snooze_finding(
        self, finding_id: str, *, until_days: int, reason: str
    ) -> dict[str, Any]:
        """Snooze a finding for *until_days* days.

        POSTs to the lifecycle endpoint with state=snoozed and the number of
        days until the snooze expires.
        """
        url = f"{self._base}/api/v1/findings/{finding_id}/lifecycle"
        payload = {"state": "snoozed", "snooze_days": until_days, "reason": reason}
        try:
            resp = self._http.post(url, json=payload)
            if resp.status_code not in (404, 405):
                return self._parse(resp)
        except (httpx.RequestError, AegisAPIError):
            raise

        raise NotImplementedError(
            f"Finding lifecycle endpoint not yet implemented for finding '{finding_id}'. "
            "Upgrade the Aegis backend to enable bulk triage operations."
        )

    def assign_finding(self, finding_id: str, *, assignee: str) -> dict[str, Any]:
        """Assign a finding to an org member by email.

        POSTs to the lifecycle endpoint with state=assigned and the assignee
        email address.
        """
        url = f"{self._base}/api/v1/findings/{finding_id}/lifecycle"
        payload = {"state": "assigned", "assignee": assignee}
        try:
            resp = self._http.post(url, json=payload)
            if resp.status_code not in (404, 405):
                return self._parse(resp)
        except (httpx.RequestError, AegisAPIError):
            raise

        raise NotImplementedError(
            f"Finding lifecycle endpoint not yet implemented for finding '{finding_id}'. "
            "Upgrade the Aegis backend to enable bulk triage operations."
        )

    def mark_finding_fixed(self, finding_id: str, *, reason: str) -> dict[str, Any]:
        """Mark a finding as manually fixed.

        POSTs to the lifecycle endpoint with state=fixed.
        """
        url = f"{self._base}/api/v1/findings/{finding_id}/lifecycle"
        payload = {"state": "fixed", "reason": reason}
        try:
            resp = self._http.post(url, json=payload)
            if resp.status_code not in (404, 405):
                return self._parse(resp)
        except (httpx.RequestError, AegisAPIError):
            raise

        raise NotImplementedError(
            f"Finding lifecycle endpoint not yet implemented for finding '{finding_id}'. "
            "Upgrade the Aegis backend to enable bulk triage operations."
        )

    # ------------------------------------------------------------------
    # Chain graph
    # ------------------------------------------------------------------

    def get_chain(self, *, org: str, chain_id: str) -> dict[str, Any]:
        """Return chain detail by ID."""
        url = f"{self._base}/api/v1/chains/{chain_id}"
        resp = self._http.get(url, params={"org": org})
        return self._parse(resp)

    # ------------------------------------------------------------------
    # Go/No-Go decision
    # ------------------------------------------------------------------

    def get_decision(
        self,
        *,
        org: str,
        repo: str,
        service_id: str | None = None,
        block_on: list[str] | None = None,
    ) -> dict[str, Any]:
        """Return a go/no-go decision for the current branch.

        Calls the backend's POST /api/v1/decisions/go-no-go endpoint.  When
        the backend is older than Phase 56 (endpoint 404/405), gracefully
        degrades to the local heuristic so existing CI gates keep working.
        """
        block_severities = {s.lower() for s in (block_on or ["critical"])}

        url = f"{self._base}/api/v1/decisions/go-no-go"
        body: dict[str, Any] = {"org_id": org, "repo": repo}
        policy: dict[str, Any] = {}
        if block_on:
            policy["block_on"] = list(block_on)
        # TODO(service-scoping): backend policy schema only accepts `block_on`
        # today; `service_id` would be silently discarded by parse_policy, so
        # we drop it on the wire to avoid implying scope we don't enforce.
        # When the backend honors service scoping, plumb `service_id` through
        # the policy dict here.
        _ = service_id
        if policy:
            body["policy"] = policy

        try:
            resp = self._http.post(url, json=body)
        except httpx.RequestError:
            # Network-level failure (DNS, connection refused, timeout) —
            # surface to the operator instead of masking with a local result.
            raise

        if resp.status_code in (404, 405):
            # Endpoint missing on older self-hosted backends — degrade locally.
            return self._local_decision_heuristic(
                org=org,
                repo=repo,
                block_severities=block_severities,
            )
        # Any other non-2xx (5xx, 401/403, etc.) must bubble up via _parse so
        # operators see real failures rather than a silent local fallback.
        return self._parse(resp)

    # NOTE: ``_local_decision_heuristic`` is a compatibility shim for
    # self-hosted deployments that have not yet picked up the Phase 56
    # ``/api/v1/decisions/go-no-go`` endpoint. It is the second source of
    # truth for go/no-go logic.
    #
    # Drift risk: the canonical implementation lives in
    # ``backend/src/decisions/service.py``. If that heuristic evolves
    # (e.g. new severity weighting, KEV/EPSS inputs, service scoping),
    # this fallback must evolve in lockstep — otherwise CI gates will
    # render different verdicts depending on backend version.
    #
    # Removal plan: drop this method (and the 404/405 fallback path in
    # ``get_decision``) once the minimum supported backend version
    # ships the decision endpoint unconditionally.
    def _local_decision_heuristic(
        self,
        *,
        org: str,
        repo: str,
        block_severities: set[str],
    ) -> dict[str, Any]:
        """Local go/no-go heuristic when the backend decision endpoint is absent.

        Fetches open findings and blocks if any match the requested severities.
        Tagged with source=local so callers can distinguish from a backend decision.
        """
        findings = self.get_findings(org=org, repo=repo)
        blockers = [
            f for f in findings
            if _extract_severity(f).lower() in block_severities
            and f.get("state", "open") == "open"
        ]
        if blockers:
            decision = "block"
            rationale = (
                f"{len(blockers)} open finding(s) at or above required severity "
                f"({', '.join(sorted(block_severities))})."
            )
        else:
            decision = "allow"
            rationale = f"No open findings at severity: {', '.join(sorted(block_severities))}."

        return {
            "decision": decision,
            "blockers": blockers,
            "rationale": rationale,
            "source": "local",
        }

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _scanner_prefix(self, scanner_type: str) -> str:
        prefix = SCANNER_ENDPOINT_MAP.get(scanner_type.lower())
        if not prefix:
            raise AegisAPIError(
                f"Unknown scanner type '{scanner_type}'. "
                f"Valid values: {', '.join(SCANNER_ENDPOINT_MAP)}"
            )
        return prefix

    def _parse(self, resp: httpx.Response) -> Any:
        """Raise AegisAPIError on HTTP errors; return parsed JSON otherwise."""
        if resp.status_code >= 400:
            try:
                detail = resp.json().get("detail") or resp.json().get("error") or resp.text
            except Exception:
                detail = resp.text
            raise AegisAPIError(detail, status_code=resp.status_code)
        try:
            return resp.json()
        except Exception as exc:
            raise AegisAPIError(f"Invalid JSON response: {exc}") from exc

    # ------------------------------------------------------------------
    # CISA KEV
    # ------------------------------------------------------------------

    def get_kev_entry(self, cve_id: str) -> dict[str, Any]:
        """Return a single KEV entry. Raises AegisAPIError(404) if not in catalog."""
        url = f"{self._base}/api/v1/kev/{cve_id.upper()}"
        resp = self._http.get(url)
        return self._parse(resp)

    def get_kev_recent(self, days: int = 30) -> dict[str, Any]:
        """Return recently-added KEV entries."""
        url = f"{self._base}/api/v1/kev/recent"
        resp = self._http.get(url, params={"days": days})
        return self._parse(resp)

    def get_kev_exposure_summary(self, org: str) -> dict[str, Any]:
        """Return KEV exposure summary for the given org."""
        url = f"{self._base}/api/v1/kev/exposure-summary"
        resp = self._http.get(url, params={"org": org})
        return self._parse(resp)

    # ------------------------------------------------------------------
    # EPSS
    # ------------------------------------------------------------------

    def get_epss_score(self, cve_id: str) -> dict[str, Any]:
        """Return the EPSS score for a CVE. Raises AegisAPIError(404) if not in feed."""
        url = f"{self._base}/api/v1/epss/scores/{cve_id.upper()}"
        resp = self._http.get(url)
        return self._parse(resp)

    def get_epss_top(self, org_id: str, limit: int = 20) -> dict[str, Any]:
        """Return open findings for an org ranked by EPSS score, descending."""
        url = f"{self._base}/api/v1/epss/top"
        resp = self._http.get(url, params={"org_id": org_id, "limit": limit})
        return self._parse(resp)

    def trigger_epss_refresh(self) -> dict[str, Any]:
        """Trigger an immediate EPSS feed refresh (admin endpoint)."""
        url = f"{self._base}/api/v1/epss/refresh"
        resp = self._http.post(url)
        return self._parse(resp)

    def close(self) -> None:
        self._http.close()

    def __enter__(self) -> "AegisClient":
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()


def _extract_severity(finding: dict) -> str:
    """Pull severity from whichever nested location the scanner uses."""
    # Dependencies scanner shape
    sec_adv = finding.get("security_advisory") or {}
    if sec_adv.get("severity"):
        return sec_adv["severity"]
    # Code scanning / secrets
    sev = finding.get("severity") or finding.get("rule", {}).get("severity", "")
    return sev


# Translates the CLI's per-scanner vocabulary (long form, what the per-scanner
# REST endpoints accept) into the public shorthand the aggregated
# /api/v1/findings endpoint validates against.
_CLI_TO_PUBLIC_SCANNER = {
    "dependencies": "deps",
    "deps": "deps",
    "code_scanning": "sast",
    "sast": "sast",
    "secrets": "secrets",
    "containers": "container",
    "container_scanning": "container",
    "container": "container",
}


def _to_public_scanner(name: str) -> str:
    """Map a CLI scanner alias to the endpoint's public shorthand.

    Unknown values pass through unchanged so the backend produces a clear 400
    rather than the CLI silently swallowing typos.
    """
    return _CLI_TO_PUBLIC_SCANNER.get(name.lower(), name.lower())
