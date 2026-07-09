"""Deep-audit finding lifecycle hooks.

Identity key: {repo}:{file}:{check_id}:{resource} — line-independent, so a
finding keeps its triage state when an unrelated edit shifts its line. The
resource is the endpoint (e.g. "POST /api/x/{id}"), which distinguishes multiple
findings in one router file.
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Any

from src.shared.lifecycle import LifecycleHooks

if TYPE_CHECKING:
    from src.shared.lifecycle import ScanContext


def deep_audit_identity(repo: str, file: str, check_id: str, resource: str) -> str:
    def _esc(v: str) -> str:
        return str(v).replace(":", "%3A")

    return f"{_esc(repo)}:{_esc(file)}:{_esc(check_id)}:{_esc(resource)}"


class DeepAuditHooks(LifecycleHooks):
    tool = "deep_audit"

    def compute_identity_key(self, raw: dict[str, Any]) -> str:
        return deep_audit_identity(
            repo=str(raw.get("repo_full_name") or ""),
            file=str(raw.get("file") or ""),
            check_id=str(raw.get("check_id") or ""),
            resource=str(raw.get("resource") or ""),
        )

    def initial_state(self, raw: dict[str, Any]) -> str:
        return "open"

    def extract_repo(self, raw: dict[str, Any]) -> str | None:
        return raw.get("repo_full_name")

    def extract_severity(self, raw: dict[str, Any]) -> str | None:
        return raw.get("severity")

    def extract_engine(self, raw: dict[str, Any]) -> str | None:
        return "llm"

    def extract_detail(self, raw: dict[str, Any]) -> dict:
        detail: dict[str, Any] = {
            "checkId": raw.get("check_id", ""),
            "ruleName": raw.get("check_id", ""),
            "title": raw.get("title", ""),
            "filePath": raw.get("file", ""),
            "startLine": raw.get("line", 0),
            "resource": raw.get("resource", ""),
            "severity": raw.get("severity", ""),
            "fingerprint": raw.get("fingerprint", ""),
            "repoHtmlUrl": raw.get("repo_html_url", ""),
        }
        # Rich verification output the runner produced (verdict + chain + evidence
        # + reproduction-in-metadata) plus the CWE (drives the OWASP badge) and the
        # concrete fix. Carried through so the drawer renders the full flow.
        for key in (
            "verdict", "evidence", "exploit_chain", "verification_metadata",
            "recommended_fix", "cwe", "code_window", "code_window_start_line",
        ):
            val = raw.get(key)
            if val is not None:
                detail[key] = val
        return detail

    def extract_file_location(self, raw: dict) -> tuple[str, int] | None:
        file = raw.get("file") or ""
        line = raw.get("line") or 0
        if file and line:
            return file, int(line)
        return None

    def should_mark_fixed(self, identity_key: str, prev_detail: dict, **kwargs) -> bool:
        return True

    def canonical_external_ref(self, ctx: "ScanContext", raw: dict[str, Any]) -> tuple[str, str]:
        from src.assets.refs import repo_ref
        repo = self.extract_repo(raw)
        if not repo:
            raise ValueError(f"{ctx.tool} finding has no repo: {raw!r}")
        if ctx.source_type is None:
            raise ValueError("ScanContext.source_type is required for asset resolution")
        name = repo.split("/", 1)[-1]
        return repo_ref(ctx.source_type, ctx.org, name), "repo"


deep_audit_hooks = DeepAuditHooks()
