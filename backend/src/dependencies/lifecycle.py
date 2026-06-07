"""Dependencies finding lifecycle hooks for the shared lifecycle engine.

Identity key: {repo}::{packageName}::{ecosystem}::{advisoryId}::{manifestPath}
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Any

from src.shared.lifecycle import LifecycleHooks

if TYPE_CHECKING:
    from src.shared.lifecycle import ScanContext


class DependenciesHooks(LifecycleHooks):
    tool = "dependencies"

    def compute_identity_key(self, raw: dict[str, Any]) -> str:
        repo: str = (raw.get("repository") or {}).get("name", "")
        pkg: dict = (raw.get("dependency") or {}).get("package") or {}
        package_name: str = pkg.get("name", "")
        ecosystem: str = pkg.get("ecosystem", "")
        advisory_id: str = (raw.get("security_advisory") or {}).get("ghsa_id", "")
        manifest_path: str = (raw.get("dependency") or {}).get("manifest_path", "")
        return f"{repo}::{package_name}::{ecosystem}::{advisory_id}::{manifest_path}"

    def initial_state(self, raw: dict[str, Any]) -> str:
        return "open" if self.has_fix(raw) else "deferred"

    def extract_repo(self, raw: dict[str, Any]) -> str | None:
        repo = raw.get("repository") or {}
        return repo.get("full_name") or repo.get("name")

    def extract_severity(self, raw: dict[str, Any]) -> str | None:
        return (raw.get("security_advisory") or {}).get("severity")

    def extract_detail(self, raw: dict[str, Any]) -> dict:
        advisory = raw.get("security_advisory") or {}
        vuln = raw.get("security_vulnerability") or {}
        dep = raw.get("dependency") or {}
        pkg = dep.get("package") or {}
        cvss = advisory.get("cvss") or {}
        return {
            "packageName": pkg.get("name", ""),
            "ecosystem": pkg.get("ecosystem", ""),
            "advisoryId": advisory.get("ghsa_id", ""),
            "cveId": advisory.get("cve_id"),
            "vulnerableVersionRange": vuln.get("vulnerable_version_range", ""),
            "patchedVersion": (vuln.get("first_patched_version") or {}).get("identifier"),
            "manifestPath": dep.get("manifest_path", ""),
            "advisoryUrl": advisory.get("html_url", ""),
            "cvssScore": cvss.get("score"),
            "cvssVector": cvss.get("vector_string"),
            "summary": advisory.get("summary", ""),
            "description": advisory.get("description", ""),
            "publishedAt": advisory.get("published_at", ""),
            "advisoryUpdatedAt": advisory.get("updated_at", ""),
            "references": advisory.get("references", []),
            "currentVersion": raw.get("current_version"),
            "source": raw.get("source", "git"),
            "scanner": raw.get("scanner", "grype"),
            "manifestSnippet": raw.get("manifest_snippet"),
            "manifestMatchLine": raw.get("manifest_match_line"),
            "matchedBy": raw.get("matched_by", []),
        }

    def has_fix(self, raw: dict[str, Any]) -> bool:
        first_patched = (raw.get("security_vulnerability") or {}).get("first_patched_version")
        if not first_patched:
            return False
        if isinstance(first_patched, dict):
            return bool(first_patched.get("identifier"))
        return bool(first_patched)

    def canonical_external_ref(self, ctx: "ScanContext", raw: dict[str, Any]) -> tuple[str, str]:
        from src.assets.refs import repo_ref
        repo = self.extract_repo(raw)
        if not repo:
            raise ValueError(f"{ctx.tool} finding has no repo: {raw!r}")
        if ctx.source_type is None:
            raise ValueError("ScanContext.source_type is required for asset resolution")
        # extract_repo may return "owner/name" (full_name) — keep only the repo name
        name = repo.split("/", 1)[-1]
        return repo_ref(ctx.source_type, ctx.org, name), "repo"


# Singleton for import convenience
dependencies_hooks = DependenciesHooks()
