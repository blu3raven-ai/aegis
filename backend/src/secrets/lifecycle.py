"""Secrets finding lifecycle hooks for the shared lifecycle engine.

Identity key: {secretIdentity} (SHA256 hash — no org prefix, org is a column).
Secrets are org-scoped, not repo-scoped. Locations (repo, file, line, commit)
are stored in detail.locations[].
"""
from __future__ import annotations

from typing import Any

from src.shared.lifecycle import LifecycleHooks
from src.secrets.store import build_secret_identity


class SecretsHooks(LifecycleHooks):
    tool = "secrets"

    def compute_identity_key(self, raw: dict[str, Any]) -> str:
        return raw.get("secretIdentity") or build_secret_identity(raw) or ""

    def initial_state(self, raw: dict[str, Any]) -> str:
        return "open"

    def should_mark_fixed(self, identity_key: str, prev_detail: dict, **kwargs) -> bool:
        return False

    def extract_repo(self, raw: dict[str, Any]) -> str | None:
        return None  # Secrets are org-scoped, locations in detail

    def extract_severity(self, raw: dict[str, Any]) -> str | None:
        return raw.get("severity") or "high"

    def extract_detail(self, raw: dict[str, Any]) -> dict:
        return {
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


secrets_hooks = SecretsHooks()
