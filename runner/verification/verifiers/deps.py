"""Per-finding dependency (SCA) reachability verification.

Emits a recall-safe tri-state reachability SIGNAL (``reachable`` / ``no_path`` /
``unknown``) into ``verification_metadata`` — never a hide decision. The backend
fuses reachability with KEV/EPSS into the categorical verdict at ingest, so the
``verdict`` here stays conservative (``needs_verify``).
"""
from __future__ import annotations

import logging
import os
import re
from pathlib import Path

from pydantic import ValidationError

from runner.scanners.dependencies.advisory_enrichment import (
    AdvisoryDetail,
    fetch_advisory_details,
)
from runner.verification.critic import verify_citations
from runner.verification.pipeline import VerificationResult
from runner.verification.prompts.deps import (
    DEPS_REACHABILITY_SYSTEM,
    deps_reachability_user_message,
)
from runner.verification.schemas.verdict import DepsReachabilityResponse

logger = logging.getLogger(__name__)

_MAX_TOKENS = 700

# Bound the local source scan so a huge monorepo can't stall the pre-filter.
_SCAN_MAX_FILES = 2000
_SCAN_MAX_HITS = 20
_SKIP_DIRS = frozenset({
    ".git", "node_modules", ".venv", "venv", "env", "dist", "build",
    "__pycache__", ".mypy_cache", ".pytest_cache", ".tox", "vendor", ".next",
    "target", ".gradle",
})
_PY_EXT = frozenset({".py", ".pyi"})
_JS_EXT = frozenset({".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"})

_PY_ECOSYSTEMS = frozenset({"pypi", "python", "pip", "poetry"})
_JS_ECOSYSTEMS = frozenset({"npm", "node", "javascript", "typescript", "yarn", "pnpm"})

_UPPER_BOUND_RE = re.compile(r"<\s*([0-9][^\s,]*)")


def verify_deps_finding(
    *,
    finding: dict,
    repo_root: str,
    llm,
    escalation_llm=None,
    advisory_tool=fetch_advisory_details,
) -> VerificationResult:
    """Reachability verdict for one dependency finding.

    Deterministic pre-filter first: a package that is never imported has no path
    to its vulnerable code, so it short-circuits to ``no_path`` with no LLM spend.
    An imported package is judged by a single-shot LLM call; a ``no_path`` claim
    only stands when its citations are grounded in the repo, otherwise it
    downgrades to ``unknown`` (recall safety — never silently suppress).

    ``escalation_llm`` is the optional frontier tier. When it is ``None`` the flow
    is identical to the single-tier path. Escalation retries the single reachability
    call on a *schema* failure — the default tier couldn't emit a valid tri-state —
    so a stronger model gets one recall shot at producing a signal the default tier
    failed to produce. The citation-grounding rule still gates any ``no_path`` the
    frontier tier emits, so escalation can only surface a real signal, never hide one.
    ``verification_metadata["tier"]`` records which tier produced the signal and
    ``["escalated"]`` marks that escalation fired.
    """
    metadata: dict = {
        "model": getattr(llm, "_model", "unknown"),
        "prompt_hashes": [],
        "scanner": "dependencies_scanning",
        "tier": "default",
    }

    pkg = (finding.get("packageName") or finding.get("package") or "").strip()
    version = (finding.get("packageVersion") or finding.get("version") or "").strip()
    advisory_id = (
        finding.get("cve") or finding.get("advisoryId") or finding.get("advisory_id") or ""
    ).strip()
    ecosystem = (finding.get("ecosystem") or "").strip().lower()

    advisory = _lookup_advisory(advisory_id, advisory_tool)
    recommended_fix = _recommended_fix(pkg, version, advisory)
    if recommended_fix:
        metadata["recommended_fix"] = recommended_fix

    call_sites = _find_import_sites(repo_root, pkg, ecosystem)

    # Pre-filter: not imported anywhere → no reachable path, no LLM spend.
    if not call_sites:
        metadata["reachability"] = "no_path"
        metadata["reason"] = "package_not_imported"
        return VerificationResult(
            verdict="needs_verify",
            exploit_chain="",
            evidence=[{
                "kind": "context",
                "snippet": f"package '{pkg}' is not imported or referenced anywhere in the repository",
            }],
            tokens_in=0,
            tokens_out=0,
            verification_metadata=metadata,
        )

    # The tier the reachability call runs on; escalation promotes it.
    active_llm = llm
    reachability_messages = [
        {"role": "system", "content": DEPS_REACHABILITY_SYSTEM},
        {
            "role": "user",
            "content": deps_reachability_user_message(
                finding, _advisory_context(advisory), call_sites
            ),
        },
    ]

    resp = active_llm.chat(
        reachability_messages,
        temperature=0.0,
        max_tokens=_MAX_TOKENS,
    )
    metadata["prompt_hashes"].append(resp.prompt_hash)
    tokens_in = resp.tokens_in
    tokens_out = resp.tokens_out

    try:
        model = DepsReachabilityResponse.model_validate_json(resp.content)
    except (ValidationError, ValueError) as exc:
        # Escalate a schema failure — not a substantive signal — to the frontier
        # tier: the default model couldn't emit a valid tri-state, so a stronger
        # model gets one recall shot. The grounding rule below still gates any
        # ``no_path`` the frontier tier emits, so this can only surface a real
        # signal, never hide one.
        if escalation_llm is not None:
            logger.info(
                "deps reachability default-tier schema failure: %s — retrying on frontier",
                exc,
            )
            metadata["escalated"] = True
            metadata["tier"] = "frontier"
            metadata["model"] = getattr(escalation_llm, "_model", "unknown")
            active_llm = escalation_llm
            resp = active_llm.chat(
                reachability_messages,
                temperature=0.0,
                max_tokens=_MAX_TOKENS,
            )
            metadata["prompt_hashes"].append(resp.prompt_hash)
            tokens_in += resp.tokens_in
            tokens_out += resp.tokens_out
            try:
                model = DepsReachabilityResponse.model_validate_json(resp.content)
            except (ValidationError, ValueError) as exc2:
                logger.warning(
                    "deps reachability response failed schema validation on both "
                    "tiers: %s — falling back",
                    exc2,
                )
                metadata["reachability"] = "unknown"
                metadata["reason"] = f"schema_invalid: {exc2}"
                return VerificationResult(
                    verdict="needs_verify",
                    exploit_chain="",
                    evidence=call_sites,
                    tokens_in=tokens_in,
                    tokens_out=tokens_out,
                    verification_metadata=metadata,
                )
        else:
            logger.warning(
                "deps reachability response failed schema validation: %s — falling back",
                exc,
            )
            metadata["reachability"] = "unknown"
            metadata["reason"] = f"schema_invalid: {exc}"
            return VerificationResult(
                verdict="needs_verify",
                exploit_chain="",
                evidence=call_sites,
                tokens_in=tokens_in,
                tokens_out=tokens_out,
                verification_metadata=metadata,
            )

    reachability = model.reachability
    # Grounding MUST be judged against the model's own citations — never the
    # deterministic import sites. Those sites prove the package is imported, so
    # borrowing them (via `or call_sites`) would let a `no_path` the model cited
    # nothing for masquerade as grounded and hide a real, reachable vuln.
    model_evidence = model.evidence or []

    # Recall safety: a `no_path` claim may only hide a path if its own citations
    # are grounded in the repo. No citations, or an ungrounded one → `unknown`.
    if reachability == "no_path":
        unverified, _ = verify_citations(model_evidence, repo_root)
        if not model_evidence or unverified:
            metadata["reachability"] = "unknown"
            metadata["ungrounded_no_path"] = unverified or ["no_citations"]
            return VerificationResult(
                verdict="needs_verify",
                exploit_chain="",
                evidence=call_sites,
                tokens_in=tokens_in,
                tokens_out=tokens_out,
                verification_metadata=metadata,
            )

    # Grounding decided — call_sites may now serve as display evidence when the
    # model returned none.
    evidence = model_evidence or call_sites
    metadata["reachability"] = reachability
    return VerificationResult(
        verdict="needs_verify",
        exploit_chain="",
        evidence=evidence,
        tokens_in=tokens_in,
        tokens_out=tokens_out,
        verification_metadata=metadata,
    )


def _lookup_advisory(advisory_id: str, advisory_tool) -> AdvisoryDetail | None:
    if not advisory_id:
        return None
    try:
        details = advisory_tool([advisory_id])
    except Exception as exc:  # noqa: BLE001 — advisory enrichment is best-effort
        logger.debug("advisory lookup failed for %s: %s", advisory_id, exc)
        return None
    if not isinstance(details, dict):
        return None
    return details.get(advisory_id)


def _recommended_fix(pkg: str, version: str, advisory: AdvisoryDetail | None) -> dict | None:
    """Deterministic upgrade suggestion from the advisory's fixed-version bound."""
    if not advisory or not pkg:
        return None
    match = _UPPER_BOUND_RE.search(advisory.vulnerable_version_range or "")
    if not match:
        return None
    fixed = match.group(1)
    return {
        "packageName": pkg,
        "fromVersion": version or None,
        "toVersion": fixed,
        "title": f"Upgrade {pkg} to {fixed}",
    }


def _advisory_context(advisory: AdvisoryDetail | None) -> str:
    if advisory is None:
        return ""
    parts: list[str] = []
    if advisory.summary:
        parts.append(f"  summary: {advisory.summary}")
    if advisory.description:
        parts.append(f"  description: {advisory.description}")
    if advisory.vulnerable_version_range:
        parts.append(f"  affected versions: {advisory.vulnerable_version_range}")
    if advisory.cwes:
        parts.append(f"  cwes: {', '.join(advisory.cwes)}")
    return "\n".join(parts)


def _import_patterns(pkg: str, ecosystem: str) -> tuple[list[re.Pattern], frozenset[str]]:
    """Return (regexes, file-extensions) for the finding's ecosystem.

    Unknown ecosystem falls back to scanning both language families — conservative:
    a false "imported" only costs one LLM call, a false "not imported" would
    wrongly hide the finding.
    """
    py_token = re.escape(pkg.replace("-", "_"))
    js_pkg = re.escape(pkg)

    py = [
        re.compile(rf"^\s*(?:import|from)\s+{py_token}(?:\.|\s|,|$)"),
    ]
    js = [
        re.compile(rf"""require\(\s*['"]{js_pkg}(?:/[^'"]*)?['"]\s*\)"""),
        re.compile(rf"""from\s+['"]{js_pkg}(?:/[^'"]*)?['"]"""),
        re.compile(rf"""import\s+['"]{js_pkg}(?:/[^'"]*)?['"]"""),
    ]

    if ecosystem in _PY_ECOSYSTEMS:
        return py, _PY_EXT
    if ecosystem in _JS_ECOSYSTEMS:
        return js, _JS_EXT
    return py + js, _PY_EXT | _JS_EXT


def _find_import_sites(repo_root: str, pkg: str, ecosystem: str) -> list[dict]:
    """Grep the repo for import/require statements referencing ``pkg``.

    Cheap, conservative source scan — matches the package name token in an import
    position rather than any mention, to avoid comments/strings inflating hits.
    """
    if not pkg:
        return []

    patterns, extensions = _import_patterns(pkg, ecosystem)

    try:
        root = Path(repo_root).resolve()
    except OSError:
        return []

    sites: list[dict] = []
    scanned = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS and not d.startswith(".")]
        for name in filenames:
            if scanned >= _SCAN_MAX_FILES or len(sites) >= _SCAN_MAX_HITS:
                return sites
            if Path(name).suffix not in extensions:
                continue
            path = Path(dirpath) / name
            scanned += 1
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            rel = path.relative_to(root).as_posix()
            for lineno, line in enumerate(text.splitlines(), start=1):
                if any(p.search(line) for p in patterns):
                    sites.append({
                        "kind": "import_site",
                        "file": rel,
                        "line": lineno,
                        "snippet": line.strip(),
                    })
                    if len(sites) >= _SCAN_MAX_HITS:
                        return sites
    return sites
