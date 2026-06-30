# backend/src/containers/lifecycle.py
"""Container scanning lifecycle hooks — finding state management."""
from __future__ import annotations

from typing import TYPE_CHECKING

from src.shared.lifecycle import LifecycleHooks

if TYPE_CHECKING:
    from src.shared.lifecycle import ScanContext


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
            "layerCount": raw.get("layerCount"),
            "sizeBytes": raw.get("sizeBytes"),
            "baseOs": raw.get("baseOs"),
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
            "matchSource": raw.get("match_source"),
        }

    def has_fix(self, raw: dict) -> bool:
        fpv = (
            raw.get("security_vulnerability", {})
            .get("first_patched_version")
        )
        return bool(fpv and fpv.get("identifier"))

    def canonical_external_ref(self, ctx: "ScanContext", raw: dict) -> tuple[str, str]:
        from src.assets.refs import image_ref
        if ctx.source_type is None:
            raise ValueError("ScanContext.source_type is required for asset resolution")
        # Prefer the top-level imageName/imageTag fields set by the normalizer.
        # Fall back to repository.name (image_name without tag) for legacy shapes.
        image_name = raw.get("imageName") or raw.get("repository", {}).get("name")
        image_tag = raw.get("imageTag") or "latest"
        if not image_name:
            raise ValueError(f"container finding has no image: {raw!r}")
        # Strip any registry hostname prefix (e.g. "ghcr.io/") — ctx.source_type
        # already carries the registry short name.
        if "/" in image_name:
            parts = image_name.split("/", 1)
            # Detect a registry hostname: contains a dot or is "localhost"
            if "." in parts[0] or parts[0] == "localhost":
                image_name = parts[1]
        return image_ref(ctx.source_type, image_name, image_tag), "image"


container_scanning_hooks = ContainerScanningHooks()
