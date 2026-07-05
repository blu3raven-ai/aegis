"""IaC (checkov) finding lifecycle hooks for the shared lifecycle engine.

Identity key: {repo}:{file}:{check_id}:{resource} — line-independent, so a
finding keeps its identity (and triage state) when an unrelated edit shifts its
line number. The check_id + resource pair distinguishes multiple findings in one
file; the line is mutable detail, not identity.
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Any

from src.shared.lifecycle import LifecycleHooks

if TYPE_CHECKING:
    from src.shared.lifecycle import ScanContext


def iac_finding_identity(repo: str, file: str, check_id: str, resource: str) -> str:
    """Stable, line-independent identity key for an IaC finding."""
    def _esc(v: str) -> str:
        return str(v).replace(":", "%3A")

    return f"{_esc(repo)}:{_esc(file)}:{_esc(check_id)}:{_esc(resource)}"


class IacScanningHooks(LifecycleHooks):
    tool = "iac_scanning"

    def compute_identity_key(self, raw: dict[str, Any]) -> str:
        return iac_finding_identity(
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
        return raw.get("engine") or "checkov"

    def extract_detail(self, raw: dict[str, Any]) -> dict:
        detail: dict[str, Any] = {
            "checkId": raw.get("check_id", ""),
            "ruleName": raw.get("check_id", ""),
            "title": raw.get("title", ""),
            "filePath": raw.get("file", ""),
            "startLine": raw.get("line", 0),
            "resource": raw.get("resource", ""),
            "severity": raw.get("severity", ""),
            "guideline": raw.get("guideline", ""),
            "fingerprint": raw.get("fingerprint", ""),
            "repoHtmlUrl": raw.get("repo_html_url", ""),
        }
        # Verification fields are present only when LLM verification ran;
        # the code window is always emitted by the runner when source is readable.
        for key in (
            "verdict", "evidence", "exploit_chain", "verification_metadata",
            "recommended_fix", "code_window", "code_window_start_line",
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


# Singleton for import convenience
iac_scanning_hooks = IacScanningHooks()
