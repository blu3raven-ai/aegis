"""Deep-audit engine: hunter -> skeptic -> critic over a repo, per lens.

Shared by every lens. The hunter proposes candidate findings from handler files;
the skeptic tries to refute each with expanded context; the critic grep-checks
the cited lines. Verdict: refuted -> ruled_out, ungrounded citations ->
needs_verify, otherwise confirmed. All LLM calls run concurrently under the
locked scan budget.
"""
from __future__ import annotations

import concurrent.futures
import hashlib
import logging
import re
import threading
from pathlib import Path

from runner.scanners.deep_audit.lenses.base import Lens
from runner.scanners.deep_audit.schemas import (
    AuditFinding,
    AuditHunterResponse,
    AuditSkepticResponse,
)
from runner.scanners.deep_audit.targets import select_files
from runner.verification.budget import ScanBudget
from runner.verification.critic import verify_citations

logger = logging.getLogger(__name__)

# Markers of where authorization is applied, gathered repo-wide to give the
# skeptic a shot at finding a compensating control it can't see in the handler.
_AUTH_MARKERS = re.compile(
    r"Depends\(Permission|has_permission|require_permission|requireAuth|"
    r"IsAuthenticated|login_required|before_action|authorize|ensureLoggedIn|"
    r"@auth|middleware|current_user|resolve_asset_ids|tenant_id|owner_id",
    re.IGNORECASE,
)
_MAX_AUTH_CONTEXT_LINES = 80


def _auth_context(repo_root: str, finding: AuditFinding, max_chars: int) -> str:
    """Full handler file + a repo-wide sample of lines where auth is applied."""
    parts: list[str] = []
    try:
        handler = (Path(repo_root) / finding.file).read_text("utf-8", "replace")
        parts.append(f"# Handler file: {finding.file}\n{handler[:max_chars]}")
    except OSError:
        pass

    hits: list[str] = []
    root = Path(repo_root)
    for path in root.rglob("*"):
        if len(hits) >= _MAX_AUTH_CONTEXT_LINES:
            break
        if not path.is_file() or path.suffix not in {".py", ".js", ".ts", ".tsx", ".rb", ".go", ".java"}:
            continue
        try:
            for i, line in enumerate(path.read_text("utf-8", "replace").splitlines(), 1):
                if _AUTH_MARKERS.search(line):
                    hits.append(f"{path.relative_to(root).as_posix()}:{i}: {line.strip()[:160]}")
                    if len(hits) >= _MAX_AUTH_CONTEXT_LINES:
                        break
        except OSError:
            continue
    if hits:
        parts.append("# Where authorization is applied repo-wide (grep):\n" + "\n".join(hits))
    return "\n\n".join(parts)


def _fingerprint(repo: str, finding: AuditFinding, lens: Lens) -> str:
    key = f"{repo}:{finding.file}:{lens.check_id(finding.weakness)}:{finding.endpoint}"
    return hashlib.sha1(key.encode()).hexdigest()[:16]


def _hunt_file(lens: Lens, rel_path: str, text: str, *, llm, escalation_llm, budget: ScanBudget):
    if not budget.allow():
        return []
    messages = [
        {"role": "system", "content": lens.hunter_system},
        {"role": "user", "content": lens.hunter_user(rel_path, text)},
    ]
    try:
        result = llm.chat_json(messages, AuditHunterResponse, temperature=0.0, max_tokens=2000)
    except Exception as e:  # noqa: BLE001 — one file must not sink the scan
        logger.warning("[!] deep-audit hunter failed on %s: %s", rel_path, type(e).__name__)
        return []
    budget.record(tokens_in=result.tokens_in, tokens_out=result.tokens_out)
    if result.parsed is None and escalation_llm is not None:
        try:
            result = escalation_llm.chat_json(messages, AuditHunterResponse, temperature=0.0, max_tokens=2000)
            budget.record(tokens_in=result.tokens_in, tokens_out=result.tokens_out)
        except Exception:  # noqa: BLE001
            return []
    return list(result.parsed.findings) if result.parsed else []


def _judge_finding(lens: Lens, finding: AuditFinding, repo_root: str, *, llm, budget: ScanBudget, max_chars: int):
    """Skeptic + critic -> a verdict for one candidate finding."""
    verdict = "confirmed"
    skeptic_meta: dict = {}

    if budget.allow():
        context = _auth_context(repo_root, finding, max_chars)
        messages = [
            {"role": "system", "content": lens.skeptic_system},
            {"role": "user", "content": lens.skeptic_user(finding, context)},
        ]
        try:
            result = llm.chat_json(messages, AuditSkepticResponse, temperature=0.0, max_tokens=600)
            budget.record(tokens_in=result.tokens_in, tokens_out=result.tokens_out)
            if result.parsed and result.parsed.refuted:
                verdict = "ruled_out"
                skeptic_meta = {
                    "ruled_out_reason": {
                        "reasoning": result.parsed.reason,
                        "compensating_control": result.parsed.compensating_control,
                    }
                }
        except Exception:  # noqa: BLE001 — skeptic failure just keeps the finding
            pass

    # Critic: cited lines must actually exist. Ungrounded -> downgrade.
    if verdict == "confirmed":
        evidence_dicts = [e.model_dump() for e in finding.evidence]
        unverified, _ = verify_citations(evidence_dicts, repo_root)
        if unverified:
            verdict = "needs_verify"
            skeptic_meta["unverified_citations"] = unverified
    return verdict, skeptic_meta


def run_lens(
    repo_root: str, lens: Lens, *, llm, escalation_llm, scan_budget: ScanBudget,
    max_files: int, max_chars: int, max_workers: int, model_name: str,
    cancel_event: "threading.Event | None" = None,
) -> list[dict]:
    """Run one lens over a repo and return finding dicts (backend-shaped)."""
    files = select_files(repo_root, lens, max_files=max_files, max_chars=max_chars)
    if not files:
        return []

    # Hunter fan-out over candidate files.
    def _hunt(item):
        if cancel_event is not None and cancel_event.is_set():
            return []
        rel, text = item
        return _hunt_file(lens, rel, text, llm=llm, escalation_llm=escalation_llm, budget=scan_budget)

    candidates: list[AuditFinding] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, min(max_workers, len(files)))) as pool:
        for found in pool.map(_hunt, files):
            candidates.extend(found)
    if not candidates:
        return []

    # Skeptic + critic fan-out over candidates.
    def _judge(finding):
        if cancel_event is not None and cancel_event.is_set():
            return "needs_verify", {}
        return _judge_finding(lens, finding, repo_root, llm=llm, budget=scan_budget, max_chars=max_chars)

    verdicts: list[tuple[str, dict]]
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, min(max_workers, len(candidates)))) as pool:
        verdicts = list(pool.map(_judge, candidates))

    out: list[dict] = []
    for finding, (verdict, meta) in zip(candidates, verdicts):
        weakness = finding.weakness or "finding"
        out.append({
            "check_id": lens.check_id(weakness),
            "title": finding.title,
            "severity": finding.norm_severity(),
            "file": finding.file,
            "line": finding.line,
            "resource": finding.endpoint or lens.check_id(weakness),
            "fingerprint": _fingerprint(repo_root, finding, lens),
            "verdict": verdict,
            "evidence": [e.model_dump() for e in finding.evidence],
            "exploit_chain": finding.exploit_chain,
            "recommended_fix": finding.fix,
            "cwe": lens.cwe_for(weakness),
            "verification_metadata": {
                "engine": "llm",
                "lens": lens.key,
                "category": lens.category,
                "owasp": lens.owasp,
                "reproduction": finding.reproduction,
                "model": model_name,
                **meta,
            },
        })
    return out
