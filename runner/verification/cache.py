"""Verification cache — replay a prior LLM verdict instead of re-spending tokens.

A finding's verdict is a pure function of what the model sees: the rule, the code
window, and the reachability label. Hash those into a stable key; if the backend
already has a verified finding with that exact key, reuse its verdict and skip the
LLM call. Only unchanged findings are cached — new or edited code still verifies.
"""
from __future__ import annotations

import hashlib
import logging
from typing import Any

logger = logging.getLogger(__name__)

# Cap the code window fed into the hash so a pathological finding can't produce a
# multi-megabyte key; the leading window is what determines the verdict anyway.
_MAX_WINDOW = 4000

# Bumped whenever the hunter prompt or schema changes in a way that should
# re-verify existing findings (e.g. feeding reachability/call_chain). Without
# this, the cache replays the prior verdict for unchanged code and a prompt
# improvement never reaches findings that were already verified.
_PROMPT_VERSION = "v2:reachability-callchain"


def verification_input_hash(finding: dict[str, Any]) -> str:
    """Stable content hash of a finding's verification input (rule + location +
    code window + reachability + prompt version). Handles both SAST and IaC
    finding shapes. The prompt version busts the cache when the hunter prompt
    changes so existing findings re-verify against the new prompt."""
    rule = str(finding.get("rule_id") or finding.get("check_id") or "")
    path = str(finding.get("file_path") or finding.get("file") or "")
    line = str(finding.get("start_line") or finding.get("line") or "")
    reach = str(finding.get("reachability") or "")
    window = str(finding.get("code_window") or finding.get("snippet") or "")[:_MAX_WINDOW]
    parts = f"{_PROMPT_VERSION}|{rule}|{path}|{line}|{reach}|{window}"
    return hashlib.sha256(parts.encode("utf-8", "replace")).hexdigest()


def lookup_cache(backend, *, tool: str, hashes: list[str]) -> dict[str, dict[str, Any]]:
    """Fetch cached verification results by hash. Best-effort — a cache failure
    must never block verification, only forgo the savings."""
    if backend is None or not hashes:
        return {}
    try:
        return backend.verification_cache_lookup(tool=tool, hashes=sorted(set(hashes)))
    except Exception:  # noqa: BLE001
        logger.warning("[!] verification cache lookup failed; verifying without it", exc_info=True)
        return {}


def apply_cache_hit(copy: dict[str, Any], cached: dict[str, Any], input_hash: str) -> None:
    """Replay a cached verification onto a finding, zeroing tokens so the reused
    verdict is not counted as fresh spend."""
    copy["verdict"] = cached.get("verdict")
    copy["evidence"] = cached.get("evidence")
    copy["exploit_chain"] = cached.get("exploit_chain")
    meta = dict(cached.get("verification_metadata") or {})
    meta["cache_hit"] = True
    meta["tokens_in"] = 0
    meta["tokens_out"] = 0
    meta["verification_input_hash"] = input_hash
    copy["verification_metadata"] = meta
