"""SAST finding lifecycle hooks for the shared lifecycle engine.

Identity key: {repo}:{file_path}:{rule_id}:{snippet-fingerprint or start_line}
— a content fingerprint keeps a finding stable when edits shift its line number.
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Any

from src.code_scanning.ingest import code_finding_identity
from src.shared.lifecycle import LifecycleHooks

if TYPE_CHECKING:
    from src.shared.lifecycle import ScanContext


class CodeScanningHooks(LifecycleHooks):
    tool = "code_scanning"

    def compute_identity_key(self, raw: dict[str, Any]) -> str:
        return code_finding_identity(
            repo=str(raw.get("repo_full_name") or ""),
            file_path=str(raw.get("file_path") or ""),
            rule_id=str(raw.get("rule_id") or ""),
            start_line=raw.get("start_line") or 0,
            snippet=str(raw.get("snippet") or ""),
        )

    def initial_state(self, raw: dict[str, Any]) -> str:
        return "open"

    def extract_repo(self, raw: dict[str, Any]) -> str | None:
        return raw.get("repo_full_name")

    def extract_severity(self, raw: dict[str, Any]) -> str | None:
        return raw.get("severity")

    def extract_engine(self, raw: dict[str, Any]) -> str | None:
        return raw.get("engine")

    def extract_detail(self, raw: dict[str, Any]) -> dict:
        rule_id = raw.get("rule_id", "")
        detail: dict[str, Any] = {
            "ruleId": rule_id,
            "ruleName": raw.get("rule_name", ""),
            "filePath": raw.get("file_path", ""),
            "startLine": raw.get("start_line", 0),
            "endLine": raw.get("end_line", 0),
            "snippet": raw.get("snippet", ""),
            "message": raw.get("message", ""),
            "category": raw.get("category", ""),
            "cwe": raw.get("cwe", []),
            "owasp": raw.get("owasp", []),
            "confidence": raw.get("confidence", ""),
            "fixSuggestion": raw.get("fix_suggestion"),
            "repoHtmlUrl": raw.get("repo_html_url", ""),
            # Fields needed by AI review
            "language": raw.get("language", ""),
            "fileClass": raw.get("file_class", ""),
        }
        # Optional large fields — only store when present. The verification
        # fields (verdict/evidence/exploit_chain/verification_metadata) drive the
        # SAST verification panel; a `ruled_out` verdict also hides the finding,
        # but finding_queries applies a grounding gate before letting it do so.
        for key in (
            "recommended_fix",
            "verdict", "evidence", "exploit_chain", "verification_metadata",
            "code_flows", "code_window", "code_window_start_line", "imports", "reachability",
        ):
            val = raw.get(key)
            if val:
                detail[key] = val
        # Engine is stored on the Finding column (source of truth) — not duplicated here.
        # ruleIds is always a list (length 1 for single-engine, 2+ for merged) so
        # downstream consumers see a uniform shape. ruleId is retained for
        # backwards compatibility with existing storage/activity/lifecycle readers.
        rule_ids = raw.get("_rule_ids") or ([rule_id] if rule_id else [])
        detail["ruleIds"] = rule_ids
        return detail

    def extract_file_location(self, raw: dict) -> tuple[str, int] | None:
        file_path = raw.get("file_path") or ""
        line = raw.get("start_line") or 0
        if file_path and line:
            return file_path, int(line)
        return None

    def should_mark_fixed(self, identity_key: str, prev_detail: dict, **kwargs) -> bool:
        active_rule_ids = kwargs.get("active_rule_ids")
        if active_rule_ids is None:
            return True
        rule_id = prev_detail.get("ruleId", "")
        if rule_id and rule_id not in active_rule_ids:
            return False
        return True

    def canonical_external_ref(self, ctx: "ScanContext", raw: dict[str, Any]) -> tuple[str, str]:
        from src.assets.refs import repo_ref
        repo = self.extract_repo(raw)
        if not repo:
            raise ValueError(f"{ctx.tool} finding has no repo: {raw!r}")
        if ctx.source_type is None:
            raise ValueError("ScanContext.source_type is required for asset resolution")
        # extract_repo returns repo_full_name like "owner/repo" — keep only the repo name
        name = repo.split("/", 1)[-1]
        return repo_ref(ctx.source_type, ctx.org, name), "repo"


# Singleton for import convenience
code_scanning_hooks = CodeScanningHooks()
