"""Collapse logically-equivalent findings via conservative per-scanner keys."""
from __future__ import annotations

import dataclasses
from collections import defaultdict
from collections.abc import Sequence

_SEVERITY_ORDER = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "negligible": 1,
    "info": 1,
    "unknown": 0,
}


@dataclasses.dataclass(frozen=True)
class DedupKey:
    scanner_family: str
    components: tuple[str, ...]


@dataclasses.dataclass(frozen=True)
class DuplicateSource:
    finding_id: str
    scanner: str
    file: str | None
    line: int | None
    severity: str
    image: str | None = None


@dataclasses.dataclass
class DedupResult:
    primaries: list[dict]
    merged_count: int
    duplicate_groups: int


def deduplicate_findings(findings: Sequence[dict]) -> DedupResult:
    """Collapse duplicates; primaries gain duplicate_count + duplicate_sources fields."""
    groups: dict[DedupKey, list[dict]] = defaultdict(list)
    keyless: list[dict] = []

    for f in findings:
        key = compute_dedup_key(f)
        if key is None:
            keyless.append(f)
            continue
        groups[key].append(f)

    primaries: list[dict] = []
    merged = 0
    duplicate_groups = 0

    for key, group in groups.items():
        if len(group) == 1:
            primaries.append(group[0])
            continue
        duplicate_groups += 1
        merged += len(group) - 1
        primary = _select_primary(group)
        primary_copy = dict(primary)
        sources = [_source_from(f) for f in group]
        primary_copy["duplicate_finding_ids"] = [
            s.finding_id for s in sources if s.finding_id != _finding_id(primary)
        ]
        primary_copy["duplicate_sources"] = [dataclasses.asdict(s) for s in sources]
        primary_copy["duplicate_count"] = len(group)
        primaries.append(primary_copy)

    primaries.extend(keyless)

    return DedupResult(
        primaries=primaries,
        merged_count=merged,
        duplicate_groups=duplicate_groups,
    )


def compute_dedup_key(f: dict) -> DedupKey | None:
    scanner = (f.get("scanner") or f.get("tool") or "").lower()

    if scanner in ("dependencies_scanning", "grype", "sca"):
        adv = f.get("advisoryId") or ""
        pkg = f.get("packageName") or ""
        ver = f.get("packageVersion") or ""
        if not (adv and pkg):
            return None
        return DedupKey(scanner_family="sca", components=(adv, pkg, ver))

    if scanner in ("container", "container-scanning"):
        adv = f.get("advisoryId") or ""
        pkg = f.get("packageName") or ""
        ver = f.get("packageVersion") or ""
        digest = f.get("imageDigest") or ""
        if not (adv and pkg):
            return None
        return DedupKey(scanner_family="container", components=(adv, pkg, ver, digest))

    if scanner in ("secret_scanning", "trufflehog"):
        digest = (
            f.get("matchHash")
            or f.get("redactedMatch")
            or (f.get("match") or "")[:32]
        )
        detector = (f.get("detectorName") or f.get("rule") or "")
        if not digest or not detector:
            return None
        return DedupKey(scanner_family="secrets", components=(detector, str(digest)))

    if scanner in ("code-scanning", "semgrep", "sast"):
        rule = f.get("rule") or f.get("ruleId") or ""
        file = f.get("file") or ""
        line = str(f.get("line") or 0)
        if not rule or not file:
            return None
        return DedupKey(scanner_family="sast", components=(rule, file, line))

    if scanner in ("iac_scanning", "checkov"):
        rule = f.get("rule") or ""
        file = f.get("file") or ""
        if not rule or not file:
            return None
        return DedupKey(scanner_family="iac", components=(rule, file))

    return None


def _select_primary(group: list[dict]) -> dict:
    """Highest severity wins; ties broken by lowest id for stability."""
    return min(
        group,
        key=lambda f: (
            -_SEVERITY_ORDER.get((f.get("severity") or "").lower(), 0),
            _finding_id(f),
        ),
    )


def _finding_id(f: dict) -> str:
    return str(f.get("id") or f.get("findingId") or "?")


def _source_from(f: dict) -> DuplicateSource:
    return DuplicateSource(
        finding_id=_finding_id(f),
        scanner=str(f.get("scanner") or f.get("tool") or "?"),
        file=f.get("file") or f.get("manifestPath"),
        line=f.get("line"),
        severity=str(f.get("severity") or "unknown"),
        image=f.get("imageName"),
    )
