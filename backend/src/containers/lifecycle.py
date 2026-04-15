# backend/src/containers/lifecycle.py
"""Container scanning lifecycle hooks — finding state management."""
from __future__ import annotations

from src.shared.lifecycle import LifecycleHooks


class ContainerScanningHooks(LifecycleHooks):
    tool = "container_scanning"

    def compute_identity_key(self, raw: dict) -> str:
        """Identity: image_ref::packageName::ecosystem::advisoryId."""
        repo = raw.get("repository", {}).get("name", "")
        pkg = raw.get("dependency", {}).get("package", {}).get("name", "")
        eco = raw.get("dependency", {}).get("package", {}).get("ecosystem", "")
        adv = raw.get("security_advisory", {}).get("ghsa_id", "")
        return f"{repo}::{pkg}::{eco}::{adv}"

    def initial_state(self, raw: dict) -> str:
        return "open" if self.has_fix(raw) else "deferred"

    def extract_repo(self, raw: dict) -> str:
        return raw.get("repository", {}).get("name", "")

    def extract_severity(self, raw: dict) -> str:
        return (
            raw.get("security_advisory", {}).get("severity", "unknown")
        ).lower()

    def extract_detail(self, raw: dict) -> dict:
        adv = raw.get("security_advisory", {})
        vuln = raw.get("security_vulnerability", {})
        dep = raw.get("dependency", {}).get("package", {})
        fpv = vuln.get("first_patched_version")
        return {
            "packageName": dep.get("name"),
            "ecosystem": dep.get("ecosystem"),
            "advisoryId": adv.get("ghsa_id"),
            "cveId": adv.get("cve_id"),
            "vulnerableVersionRange": vuln.get("vulnerable_version_range"),
            "patchedVersion": fpv.get("identifier") if fpv else None,
            "manifestPath": raw.get("dependency", {}).get("manifest_path"),
            "imageName": raw.get("imageName"),
            "imageTag": raw.get("imageTag"),
            "imageDigest": raw.get("imageDigest"),
            "advisoryUrl": adv.get("html_url"),
            "cvssScore": adv.get("cvss"),
            "cvssVector": adv.get("cvss_vector"),
            "summary": adv.get("summary"),
            "description": adv.get("description"),
            "publishedAt": adv.get("published_at"),
            "advisoryUpdatedAt": adv.get("updated_at"),
            "references": adv.get("references"),
            "source": raw.get("source", "container"),
            "scanner": raw.get("scanner", "grype"),
            "matchedBy": raw.get("matched_by", ["grype"]),
            "fixState": raw.get("fixState"),
            "currentVersion": raw.get("current_version"),
        }

    def has_fix(self, raw: dict) -> bool:
        fpv = (
            raw.get("security_vulnerability", {})
            .get("first_patched_version")
        )
        return bool(fpv and fpv.get("identifier"))


container_scanning_hooks = ContainerScanningHooks()
