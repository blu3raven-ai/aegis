"""Authz audit engine: enumerate handlers, hunt for broken access control, then
DELEGATE precision to the shared verifier (skeptic + citation critic + ground-truth
carve-outs). The hunter is the only new reasoning; every verdict decision reuses
runner.verification so this stays a candidate generator, not a parallel pipeline.
"""
from __future__ import annotations

import concurrent.futures
import logging
import re
from pathlib import Path
from typing import Any

from runner.scanners.deep_audit.prompts import (
    HUNTER_SYSTEM,
    SKEPTIC_SYSTEM,
    hunter_user,
    skeptic_user,
)
from runner.scanners.deep_audit.schemas import AuthzHunterResponse
from runner.scanners.deep_audit.targets import select_files
from runner.verification.carveouts import carveout_verdict
from runner.verification.critic import verify_citations
from runner.verification.enrich import stash_confirmed_enrichment
from runner.verification.schemas.verdict import HunterResponse, SkepticResponse

logger = logging.getLogger(__name__)

# Where authorization tends to be applied — grepped repo-wide and handed to the
# skeptic so "auth is enforced elsewhere" can be proven, not guessed.
_AUTH_MARKERS = re.compile(
    r"Depends\(Permission|has_permission|require_permission|requireAuth|"
    r"IsAuthenticated|login_required|before_action|authorize|ensureLoggedIn|"
    r"@auth|middleware|current_user|resolve_asset_ids|tenant_id|owner_id",
    re.IGNORECASE,
)
_MAX_AUTH_CONTEXT_LINES = 80
_WEAKNESS_CWE = {
    "missing_authorization": "CWE-862",
    "missing_object_scope": "CWE-639",
}
_DEFAULT_CWE = "CWE-284"


def _auth_context(repo_root: str, handler_file: str, handler_text: str, max_chars: int) -> str:
    """Handler file + a repo-wide grep of auth markers (capped), so the skeptic can
    point at a compensating control it would otherwise miss."""
    parts = [f"# Handler file: {handler_file}\n{handler_text[:max_chars]}"]
    root = Path(repo_root)
    hits: list[str] = []
    for path in root.rglob("*"):
        if len(hits) >= _MAX_AUTH_CONTEXT_LINES:
            break
        if not path.is_file() or path.suffix not in {
            ".py", ".js", ".jsx", ".ts", ".tsx", ".rb", ".go", ".java", ".kt", ".php", ".cs", ".rs",
        }:
            continue
        try:
            for i, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
                if _AUTH_MARKERS.search(line):
                    hits.append(f"{path.relative_to(root).as_posix()}:{i}: {line.strip()[:160]}")
                    if len(hits) >= _MAX_AUTH_CONTEXT_LINES:
                        break
        except OSError:
            continue
    if hits:
        parts.append("# Where authorization is applied repo-wide (grep):\n" + "\n".join(hits))
    return "\n\n".join(parts)


def _hunter_model(candidate: dict) -> HunterResponse:
    """Map an authz candidate onto the shared HunterResponse so enrichment/runtime
    routing work unchanged."""
    return HunterResponse(
        title=candidate.get("title", ""),
        impact=candidate.get("title", ""),
        exploit_chain=candidate.get("exploit_chain", ""),
        evidence=candidate.get("evidence", []) or [],
        reproduction=candidate.get("reproduction", ""),
        fix=candidate.get("fix", ""),
    )


def _finalize(
    *, candidate: dict, skeptic: SkepticResponse, hunter_model: HunterResponse,
    repo_root: str, metadata: dict, accepted_risks: list | None,
    tokens_in: int, tokens_out: int,
) -> tuple[str, dict]:
    """Verdict tail, mirroring verify_iac/verify_finding: carve-out → grounded
    mitigation → citation critic → confirmed/needs_verify → enrich. Returns
    ``(verdict, metadata)``. Recall-safe: a mitigation/finding only rules out when
    its citation is grounded against the repo."""
    chain = candidate.get("exploit_chain", "")
    evidence = candidate.get("evidence", []) or []
    finding = {
        "file": candidate.get("file", ""),
        "line": candidate.get("line", 0),
        "rule": f"deep_audit.authz.{candidate.get('weakness', 'authz')}",
        "scanner": "deep_audit",
    }

    cv = carveout_verdict(
        finding, skeptic, accepted_risks=accepted_risks, chain=chain, evidence=evidence,
        metadata=metadata, critic=verify_citations, repo_root=repo_root,
        tokens_in=tokens_in, tokens_out=tokens_out,
    )
    if cv is not None:
        return cv.verdict, cv.verification_metadata

    if skeptic.mitigation_found:
        metadata["ruled_out_reason"] = {
            "file": skeptic.mitigation_file,
            "line": skeptic.mitigation_line,
            "snippet": skeptic.mitigation_snippet,
            "reasoning": skeptic.reasoning,
        }
        mitigation_evidence = [{
            "kind": "code", "file": skeptic.mitigation_file or "",
            "line": skeptic.mitigation_line or 0, "snippet": skeptic.mitigation_snippet or "",
        }]
        unverified, _ = verify_citations(mitigation_evidence, repo_root)
        if unverified:
            metadata["suppression_downgraded"] = unverified
            return "needs_verify", metadata
        return "ruled_out", metadata

    unverified, _ = verify_citations(evidence, repo_root)
    if unverified:
        metadata["unverified_citations"] = unverified
        return "needs_verify", metadata

    stash_confirmed_enrichment(metadata, hunter_model, repo_root)
    return "confirmed", metadata


def _to_finding_dict(candidate: dict, verdict: str, metadata: dict) -> dict:
    """Backend-ingest-shaped finding row for findings.jsonl."""
    weakness = candidate.get("weakness", "")
    return {
        "check_id": f"deep_audit.authz.{weakness or 'broken_access_control'}",
        "file": candidate.get("file", ""),
        "line": candidate.get("line", 0),
        "severity": candidate.get("severity", "medium"),
        "title": candidate.get("title", ""),
        "verdict": verdict,
        "evidence": candidate.get("evidence", []) or [],
        "exploit_chain": candidate.get("exploit_chain", ""),
        "verification_metadata": metadata,
        "recommended_fix": candidate.get("fix", ""),
        "cwe": _WEAKNESS_CWE.get(weakness, _DEFAULT_CWE),
        "resource": candidate.get("endpoint", ""),
    }


def audit_repo(
    repo_root: str, *, llm, escalation_llm=None, scan_budget, accepted_risks=None,
    ground_truth=None, max_workers: int = 4, max_files: int = 40, max_chars: int = 8000,
    cancel_event=None,
) -> list[dict]:
    """Run the authz audit over one checkout, returning verified finding dicts.
    No-op (empty) when no LLM is configured."""
    if llm is None:
        return []
    files = select_files(repo_root, max_files=max_files, max_chars=max_chars)
    out: list[dict] = []

    def _audit_file(entry: tuple[str, str]) -> list[dict]:
        rel, text = entry
        if (cancel_event and cancel_event.is_set()) or not scan_budget.allow():
            return []
        active = llm
        try:
            res = active.chat_json(
                [{"role": "system", "content": HUNTER_SYSTEM},
                 {"role": "user", "content": hunter_user(rel, text)}],
                AuthzHunterResponse, temperature=0.0, max_tokens=2000,
            )
            if res.parsed is None and escalation_llm is not None:
                active = escalation_llm
                res = active.chat_json(
                    [{"role": "system", "content": HUNTER_SYSTEM},
                     {"role": "user", "content": hunter_user(rel, text)}],
                    AuthzHunterResponse, temperature=0.0, max_tokens=2000,
                )
            scan_budget.record(tokens_in=res.tokens_in, tokens_out=res.tokens_out)
        except Exception:  # noqa: BLE001 — one bad file must not sink the scan
            logger.warning("[!] authz hunter failed on %s", rel, exc_info=True)
            return []
        if res.parsed is None:
            return []

        rows: list[dict] = []
        for cand in res.parsed.findings:
            if not scan_budget.allow():
                break
            candidate = cand.model_dump()
            metadata = {"model": getattr(active, "_model", "unknown"), "tier": "default",
                        "scanner": "deep_audit", "prompt_hashes": []}
            auth_ctx = _auth_context(repo_root, rel, text, max_chars)
            try:
                sk = active.chat_json(
                    [{"role": "system", "content": SKEPTIC_SYSTEM},
                     {"role": "user", "content": skeptic_user(candidate, auth_ctx, accepted_risks, ground_truth)}],
                    SkepticResponse, temperature=0.0, max_tokens=500,
                )
                scan_budget.record(tokens_in=sk.tokens_in, tokens_out=sk.tokens_out)
                skeptic = sk.parsed or SkepticResponse()
            except Exception:  # noqa: BLE001
                logger.warning("[!] authz skeptic failed on %s", rel, exc_info=True)
                skeptic = SkepticResponse()
            verdict, metadata = _finalize(
                candidate=candidate, skeptic=skeptic, hunter_model=_hunter_model(candidate),
                repo_root=repo_root, metadata=metadata, accepted_risks=accepted_risks,
                tokens_in=0, tokens_out=0,
            )
            rows.append(_to_finding_dict(candidate, verdict, metadata))
        return rows

    workers = max(1, min(max_workers, len(files) or 1))
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        for rows in pool.map(_audit_file, files):
            out.extend(rows)
    return out
