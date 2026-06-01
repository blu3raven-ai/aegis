"""SAST finding lifecycle hooks for the shared lifecycle engine.

Identity key: {repo}:{file_path}:{rule_id}:{start_line}
"""
from __future__ import annotations

from typing import Any

from src.shared.lifecycle import LifecycleHooks


class CodeScanningHooks(LifecycleHooks):
    tool = "code_scanning"

    def compute_identity_key(self, raw: dict[str, Any]) -> str:
        def _esc(v: str) -> str:
            return v.replace(":", "%3A")

        repo = _esc(str(raw.get("repo_full_name") or ""))
        path = _esc(str(raw.get("file_path") or ""))
        rule = _esc(str(raw.get("rule_id") or ""))
        line = raw.get("start_line") or 0
        return f"{repo}:{path}:{rule}:{line}"

    def initial_state(self, raw: dict[str, Any]) -> str:
        return "open"

    def extract_repo(self, raw: dict[str, Any]) -> str | None:
        return raw.get("repo_full_name")

    def extract_severity(self, raw: dict[str, Any]) -> str | None:
        return raw.get("severity")

    def extract_detail(self, raw: dict[str, Any]) -> dict:
        detail: dict[str, Any] = {
            "ruleId": raw.get("rule_id", ""),
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
        # Optional large fields — only store when present
        for key in ("code_flows", "code_window", "imports", "reachability"):
            val = raw.get(key)
            if val:
                detail[key] = val
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


# Singleton for import convenience
code_scanning_hooks = CodeScanningHooks()
