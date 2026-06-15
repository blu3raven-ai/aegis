"""Deterministic pre-LLM filter rules for SCA findings."""
from __future__ import annotations

import dataclasses
import re
from collections.abc import Sequence


_DEV_MANIFEST_PATTERNS = (
    re.compile(r"(?:^|/)requirements[-_]?(dev|test|tests|testing|ci|lint)\.txt$"),
    re.compile(r"(?:^|/)(dev|test|tests|testing|ci|lint)[-_]?requirements\.txt$"),
    re.compile(r"(?:^|/)pyproject\.toml$"),
    re.compile(r"(?:^|/)package-dev\.json$"),
)

_IMPORT_COLLECTOR_COVERED = frozenset(
    {"npm", "javascript", "typescript", "node", "pypi", "python", "pip"}
)


@dataclasses.dataclass(frozen=True)
class PrefilterDecision:
    skip_llm: bool
    verdict: str | None   # ruled_out | possible | None when not skipped
    reason: str
    metadata: dict

    def to_dict(self) -> dict:
        return {
            "skip_llm": self.skip_llm,
            "verdict": self.verdict,
            "reason": self.reason,
            "metadata": self.metadata,
        }


def prefilter_sca_finding(
    finding: dict,
    *,
    import_sites: Sequence | None = None,
) -> PrefilterDecision:
    """Return a deterministic decision for whether to skip the LLM."""
    ecosystem = (finding.get("ecosystem") or "").lower()
    manifest_path = (finding.get("manifestPath") or "").lower()

    if _looks_like_dev_manifest(manifest_path):
        return PrefilterDecision(
            skip_llm=True,
            verdict="ruled_out",
            reason="dev_only_manifest",
            metadata={"manifestPath": finding.get("manifestPath")},
        )

    # Zero sites is only meaningful when the collector covers this ecosystem.
    if (
        ecosystem in _IMPORT_COLLECTOR_COVERED
        and import_sites is not None
        and len(import_sites) == 0
    ):
        return PrefilterDecision(
            skip_llm=True,
            verdict="ruled_out",
            reason="no_import_sites",
            metadata={
                "packageName": finding.get("packageName"),
                "ecosystem": ecosystem,
            },
        )

    return PrefilterDecision(
        skip_llm=False,
        verdict=None,
        reason="none",
        metadata={},
    )


def _looks_like_dev_manifest(manifest_path: str) -> bool:
    if not manifest_path:
        return False
    # pyproject.toml mixes prod and dev — don't classify from path alone.
    if manifest_path.endswith("/pyproject.toml") or manifest_path == "pyproject.toml":
        return False
    return any(p.search(manifest_path) for p in _DEV_MANIFEST_PATTERNS if "pyproject" not in p.pattern)
