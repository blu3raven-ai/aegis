"""Group findings by repository and run the correlator agent on each group."""
from __future__ import annotations

import hashlib
import json
import logging
from collections import defaultdict
from collections.abc import Sequence
from pathlib import Path

from argus.verification.agents.base import investigate
from argus.verification.prompts.correlator import (
    CORRELATOR_SYSTEM,
    correlator_user_message,
)
from pydantic import ValidationError

from argus.verification.schemas.correlation import (
    ChainSeverity,
    CorrelatedFinding,
    CorrelationVerdict,
    CorrelatorPayload,
)
from argus.verification.schemas.evidence import coerce_evidence_list
from argus.verification.tools.advisory import make_fetch_advisory_tool
from argus.verification.tools.base import ToolRegistry
from argus.verification.tools.repo import (
    make_grep_repo_tool,
    make_read_file_range_tool,
)

logger = logging.getLogger(__name__)


_MIN_GROUP_SIZE = 2          # need at least 2 findings to form a chain
_MAX_GROUP_SIZE = 8          # cap so prompt + tool budget stay manageable
_DEFAULT_MAX_TURNS = 10


def correlate_findings(
    findings: Sequence[dict],
    *,
    repo_root_for: dict[str, Path] | Path,
    llm,
    budget=None,
    max_turns: int = _DEFAULT_MAX_TURNS,
) -> list[CorrelatedFinding]:
    """Group findings by repository; run the correlator agent on each cross-scanner group."""
    groups = _group_by_correlation_key(findings)
    if not groups:
        return []

    results: list[CorrelatedFinding] = []
    for key, group in groups.items():
        repo_root = _resolve_repo_root(key, repo_root_for)
        if repo_root is None or not repo_root.exists():
            logger.debug("correlator: repo_root unresolved for %s, skipping", key)
            continue

        tools = ToolRegistry(
            [
                make_grep_repo_tool(repo_root),
                make_read_file_range_tool(repo_root),
                make_fetch_advisory_tool(),
            ]
        )

        agent_result = investigate(
            system_prompt=CORRELATOR_SYSTEM,
            user_task=correlator_user_message(group),
            tools=tools,
            llm=llm,
            max_turns=max_turns,
            budget=budget,
        )

        parsed = _parse_correlator_output(
            agent_result.final_message,
            group=group,
            tool_call_count=len(agent_result.tool_calls),
            tokens_in=agent_result.tokens_in,
            tokens_out=agent_result.tokens_out,
            stopped_reason=agent_result.stopped_reason,
        )
        if parsed is not None:
            results.append(parsed)

    return results


def _group_by_correlation_key(findings: Sequence[dict]) -> dict[str, list[dict]]:
    by_repo: dict[str, list[dict]] = defaultdict(list)
    for f in findings:
        repo = (f.get("repository") or "").strip()
        if not repo:
            continue
        by_repo[repo].append(f)

    out: dict[str, list[dict]] = {}
    for repo, group in by_repo.items():
        if len(group) < _MIN_GROUP_SIZE:
            continue
        if len({f.get("scanner") or f.get("tool") or "?" for f in group}) < 2:
            continue
        out[repo] = group[:_MAX_GROUP_SIZE]
    return out


def _resolve_repo_root(key: str, repo_root_for) -> Path | None:
    if isinstance(repo_root_for, Path):
        return repo_root_for
    if isinstance(repo_root_for, dict):
        candidate = repo_root_for.get(key)
        if candidate is None:
            return None
        return Path(candidate)
    return None


def _parse_correlator_output(
    final_message: str,
    *,
    group: list[dict],
    tool_call_count: int,
    tokens_in: int,
    tokens_out: int,
    stopped_reason: str,
) -> CorrelatedFinding | None:
    """Map the agent's final JSON to a CorrelatedFinding. Returns None on
    junk output or no_chain verdict (we don't surface those)."""
    raw_payload = _extract_json(final_message)
    if not raw_payload:
        return None

    try:
        payload = CorrelatorPayload.model_validate(raw_payload)
    except (ValidationError, ValueError) as exc:
        logger.warning(
            "correlator response failed schema validation: %s — falling back",
            exc,
        )
        return None

    if payload.verdict == CorrelationVerdict.NO_CHAIN:
        return None

    severity_raw = (payload.chain_severity or "medium").strip().lower()
    try:
        severity = ChainSeverity(severity_raw)
    except ValueError:
        severity = ChainSeverity.MEDIUM

    src_ids = [str(i) for i in payload.source_finding_ids if i]
    if not src_ids:
        src_ids = [str(f.get("id") or f.get("findingId") or "?") for f in group]

    evidence = coerce_evidence_list(payload.evidence)

    correlation_id = _correlation_id(src_ids)
    return CorrelatedFinding(
        correlation_id=correlation_id,
        verdict=payload.verdict,
        chain_severity=severity,
        chain_description=str(payload.chain_description or "")[:4000],
        source_finding_ids=src_ids,
        evidence=evidence,
        tool_call_count=tool_call_count,
        tokens_in=tokens_in,
        tokens_out=tokens_out,
        metadata={"stopped_reason": stopped_reason},
    )


def _extract_json(text: str) -> dict | None:
    """Extract a JSON object from prose-wrapped agent output."""
    if not text:
        return None
    candidates: list[str] = []
    stripped = text.strip()
    if stripped.startswith("{") and stripped.endswith("}"):
        candidates.append(stripped)
    start = text.find("{")
    end = text.rfind("}")
    if 0 <= start < end:
        candidates.append(text[start : end + 1])
    for c in candidates:
        try:
            obj = json.loads(c)
            if isinstance(obj, dict):
                return obj
        except json.JSONDecodeError:
            continue
    return None


def _correlation_id(source_finding_ids: list[str]) -> str:
    digest = hashlib.sha1("\0".join(sorted(source_finding_ids)).encode()).hexdigest()
    return f"corr-{digest[:12]}"
