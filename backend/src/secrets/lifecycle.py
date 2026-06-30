"""Secrets finding lifecycle hooks for the shared lifecycle engine.

Identity key: {secretIdentity} (SHA256 hash — no org prefix, org is a column).
Secrets are org-scoped, not repo-scoped. Locations (repo, file, line, commit)
are stored in detail.locations[].
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Any

from src.shared.lifecycle import LifecycleHooks
from src.secrets.store import build_secret_identity

if TYPE_CHECKING:
    from src.shared.lifecycle import ScanContext


class SecretsHooks(LifecycleHooks):
    tool = "secret_scanning"

    def compute_identity_key(self, raw: dict[str, Any]) -> str:
        # Per-repo identity so each repo's occurrence is its own row (scoped by
        # that repo's grants) without the shared lifecycle's identity_key-keyed
        # maps colliding. The repo-independent secretIdentity stays in detail so
        # the UI can group a secret's per-repo findings together.
        base = raw.get("secretIdentity") or build_secret_identity(raw) or ""
        if not base:
            return ""
        repo = (raw.get("repository") or "").strip()
        return f"{base}::{repo}" if repo else base

    def initial_state(self, raw: dict[str, Any]) -> str:
        return "open"

    def should_mark_fixed(self, identity_key: str, prev_detail: dict, **kwargs) -> bool:
        return False

    def extract_repo(self, raw: dict[str, Any]) -> str | None:
        return (raw.get("repository") or "").strip() or None

    def extract_severity(self, raw: dict[str, Any]) -> str | None:
        return raw.get("severity") or "high"

    def extract_detail(self, raw: dict[str, Any]) -> dict:
        detail: dict[str, Any] = {
            "organization": raw.get("organization", ""),
            "secretIdentity": raw.get("secretIdentity", ""),
            "fingerprint": raw.get("fingerprint", ""),
            "detector": raw.get("detector") or raw.get("ruleID", ""),
            "source": raw.get("source", ""),
            "locations": raw.get("locations", []),
            "classificationHistory": raw.get("classificationHistory", []),
            "repository": raw.get("repository", ""),
            "filePath": raw.get("filePath", ""),
            "line": raw.get("line"),
            "commit": raw.get("commit") or "",
            "detectedAt": raw.get("detectedAt", ""),
            "secretSnippet": raw.get("secretSnippet", ""),
            "aiReasoning": raw.get("aiReasoning"),
            "raw": raw.get("raw") or {},
        }
        # Verification fields are present only when the runner verifier ran;
        # upsert_finding promotes them from detail onto the typed columns.
        for key in (
            "verdict", "evidence", "exploit_chain", "verification_metadata",
            "recommended_fix", "code_window", "code_window_start_line",
        ):
            val = raw.get(key)
            if val is not None:
                detail[key] = val
        return detail


    def canonical_external_ref(self, ctx: "ScanContext", raw: dict[str, Any]) -> tuple[str, str] | None:
        # Scope each secret to the repo it was found in, so it inherits that
        # repo's grants. Same secret in another repo of the source becomes its
        # own finding (shared identity_key lets the UI group them). Findings
        # without a repo (e.g. non-source scans) stay global (asset_id NULL).
        repo = self.extract_repo(raw)
        if not repo or ctx.source_type is None:
            return None
        from src.assets.refs import repo_ref

        name = repo.split("/", 1)[-1]
        return repo_ref(ctx.source_type, ctx.org, name), "repo"


secrets_hooks = SecretsHooks()
