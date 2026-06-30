"""Runner-side thin client for the remote Argus verification service.

When ``ARGUS_ENDPOINT`` is configured, verification is routed to a remote Argus
``POST /v1/verify`` instead of the in-process LLM agent loop. This module builds
the request (collecting the code each finding references, repo-jailed under
``repo_root``), POSTs the batch, and merges the verdicts back onto the findings.

It fails open: any transport or protocol error leaves the findings unverified
rather than aborting the scan.
"""
from __future__ import annotations

import logging
from pathlib import Path

import httpx

from runner.scanners._shared import JobEnv

logger = logging.getLogger(__name__)

# Cap per-file context to keep request bodies bounded; oversize files are skipped.
_MAX_CONTEXT_FILE_BYTES = 512 * 1024
_VERIFY_TIMEOUT = 120.0
_CORRELATE_TIMEOUT = 120.0
_FILE_PATH_KEYS = ("file_path", "file", "filePath")


def _resolve_inside_root(repo_root: Path, candidate: str) -> Path | None:
    """Resolve ``candidate`` under ``repo_root``, jailed against escape.

    ``candidate`` may be relative to ``repo_root`` or an absolute path that
    resolves inside it. Returns the resolved path only if it stays within
    ``repo_root`` (rejecting ``..`` and out-of-root escape); otherwise ``None``.
    Kept local so the OSS thin-client carries no dependency on the verification
    subtree (which is extracted into the Argus service).
    """
    root = repo_root.resolve()
    try:
        cand = Path(candidate)
        resolved = (cand if cand.is_absolute() else root / candidate.lstrip("/")).resolve()
        resolved.relative_to(root)
    except (ValueError, OSError):
        return None
    return resolved


def argus_configured(env: JobEnv) -> bool:
    """True when verification should be routed to a remote Argus service."""
    return bool(env.get("ARGUS_ENDPOINT"))


def _finding_paths(finding: dict) -> list[str]:
    """Repo-relative paths a finding references: its primary file + code-flow files."""
    paths: list[str] = []
    for key in _FILE_PATH_KEYS:
        val = finding.get(key)
        if isinstance(val, str) and val:
            paths.append(val)
            break
    if not paths:
        fs = ((finding.get("SourceMetadata") or {}).get("Data") or {}).get("Filesystem") or {}
        fs_file = fs.get("file")
        if isinstance(fs_file, str) and fs_file:
            paths.append(fs_file)
    for cf in finding.get("code_flows") or []:
        if isinstance(cf, dict):
            cf_file = cf.get("file")
            if isinstance(cf_file, str) and cf_file:
                paths.append(cf_file)

    seen: set[str] = set()
    deduped: list[str] = []
    for path in paths:
        if path not in seen:
            seen.add(path)
            deduped.append(path)
    return deduped


def _read_context_files(finding: dict, root: Path) -> list[dict]:
    """Read each referenced file repo-jailed under ``root``.

    Skips paths that escape the repo (``..``/absolute/symlink), are missing, or
    exceed the per-file byte cap.
    """
    files: list[dict] = []
    for rel in _finding_paths(finding):
        target = _resolve_inside_root(root, rel)
        if target is None:
            continue
        if not target.exists() or not target.is_file():
            continue
        try:
            if target.stat().st_size > _MAX_CONTEXT_FILE_BYTES:
                continue
            content = target.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        files.append({"path": rel, "content": content})
    return files


def _finding_id(finding: dict, index: int) -> str:
    fid = finding.get("id")
    return str(fid) if fid is not None else str(index)


def _fail_open(findings: list[dict], error_type: str) -> list[dict]:
    """Return findings unverified, tagged with the failure reason."""
    out: list[dict] = []
    for finding in findings:
        copy = dict(finding)
        copy["verdict"] = None
        copy.setdefault("verification_metadata", {})["skipped"] = f"argus_error:{error_type}"
        out.append(copy)
    return out


def verify_via_argus(
    *,
    scanner: str,
    findings: list[dict],
    repo_root: str,
    env: JobEnv,
) -> list[dict]:
    """Route a batch of findings to the remote Argus ``/v1/verify`` endpoint.

    Returns the findings with Argus verdicts merged in, matching the shape the
    local ``_maybe_verify`` returns so the caller's write-back is unchanged. On
    any error every finding comes back with ``verdict=None`` and a
    ``verification_metadata.skipped = "argus_error:<type>"`` marker.
    """
    if not findings:
        return []

    endpoint = env.get("ARGUS_ENDPOINT").rstrip("/")
    token = env.get("ARGUS_TOKEN")
    root = Path(repo_root)

    request_findings = []
    for index, finding in enumerate(findings):
        request_findings.append(
            {
                "finding_id": _finding_id(finding, index),
                "detail": finding,
                "code_context": {"files": _read_context_files(finding, root)},
            }
        )

    payload = {
        "scan_id": env.get("RUN_ID"),
        "scanner": scanner,
        "findings": request_findings,
    }

    try:
        response = httpx.post(
            f"{endpoint}/v1/verify",
            json=payload,
            headers={"Authorization": f"Bearer {token}"},
            timeout=_VERIFY_TIMEOUT,
        )
        response.raise_for_status()
        results = response.json().get("results")
        if not isinstance(results, list):
            raise ValueError("malformed response: 'results' is not a list")
    except Exception as exc:  # noqa: BLE001 - fail open: never abort the scan
        logger.warning(
            "[!] Argus verification failed (%s); leaving findings unverified",
            type(exc).__name__,
        )
        return _fail_open(findings, type(exc).__name__)

    by_id: dict[str, dict] = {}
    for result in results:
        if isinstance(result, dict) and result.get("finding_id") is not None:
            by_id[str(result["finding_id"])] = result

    out: list[dict] = []
    for index, finding in enumerate(findings):
        copy = dict(finding)
        result = by_id.get(_finding_id(finding, index))
        if result is None:
            copy["verdict"] = None
            copy.setdefault("verification_metadata", {})["skipped"] = "argus_no_result"
            out.append(copy)
            continue
        copy["verdict"] = result.get("verdict")
        copy["evidence"] = result.get("evidence")
        copy["exploit_chain"] = result.get("exploit_chain")
        copy["verification_metadata"] = result.get("verification_metadata") or {}
        if result.get("recommended_fix") is not None:
            copy["recommended_fix"] = result.get("recommended_fix")
        if result.get("reachability") is not None:
            copy["reachability"] = result.get("reachability")
        out.append(copy)
    return out


def correlate_via_argus(
    *,
    findings: list[dict],
    repo_root_for: dict,
    env: JobEnv,
    budget: int,
) -> list[dict]:
    """Route the aggregate correlation step to the remote Argus ``/v1/correlate``.

    Returns the server's ``correlated_findings`` as raw dicts (kept unparsed so
    this thin-client carries no dependency on the verification subtree). The
    caller parses them into the shared contract. Correlation is best-effort: any
    transport or protocol error returns ``[]`` rather than aborting the scan.
    """
    if not findings:
        return []

    endpoint = env.get("ARGUS_ENDPOINT").rstrip("/")
    token = env.get("ARGUS_TOKEN")

    request_findings = []
    for finding in findings:
        repo = (finding.get("repository") or "").strip()
        root = repo_root_for.get(repo)
        files = _read_context_files(finding, Path(root)) if root is not None else []
        request_findings.append({"detail": finding, "code_context": {"files": files}})

    payload = {"budget": budget, "findings": request_findings}

    try:
        response = httpx.post(
            f"{endpoint}/v1/correlate",
            json=payload,
            headers={"Authorization": f"Bearer {token}"},
            timeout=_CORRELATE_TIMEOUT,
        )
        response.raise_for_status()
        correlated = response.json().get("correlated_findings")
        if not isinstance(correlated, list):
            raise ValueError("malformed response: 'correlated_findings' is not a list")
    except Exception as exc:  # noqa: BLE001 - fail open: never abort the scan
        logger.warning(
            "[!] Argus correlation failed (%s); skipping correlation",
            type(exc).__name__,
        )
        return []

    return correlated
