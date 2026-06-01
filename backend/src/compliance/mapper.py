"""Rule-based compliance mapper.

Inspects a Finding's scanner type, severity, and metadata fields to produce
a list of ComplianceControlMapping rows. Each rule fires independently; a
single finding can produce multiple mappings across multiple frameworks.

Rules are intentionally kept simple and explicit. The goal is actionable
mappings, not exhaustive coverage — prefer precision over recall.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class _MappingDraft:
    """Intermediate value before ORM row creation."""
    framework: str
    control_id: str
    confidence: float
    rationale: str


def map_finding(
    *,
    scanner_type: str,
    severity: str | None,
    metadata: dict[str, Any] | None,
) -> list[_MappingDraft]:
    """Return control mapping drafts for a single finding.

    Parameters mirror the Finding ORM columns that are relevant for rules:
      - scanner_type: Finding.tool
      - severity: Finding.severity
      - metadata: Finding.detail (the JSONB blob)

    Callers are responsible for persisting the returned drafts.
    """
    mappings: list[_MappingDraft] = []
    md: dict[str, Any] = metadata or {}
    sev = (severity or "").lower()
    high_impact = sev in ("critical", "high")

    # ── Rule 1: Vulnerable components (SCA / container) ─────────────────────
    # Critical/high dependency or container image CVEs violate software
    # update controls across all three frameworks.
    if scanner_type in ("dependencies", "containers") and high_impact:
        mappings += [
            _MappingDraft("soc2", "CC6.8", 0.9, "Vulnerable software component detected"),
            _MappingDraft("iso27001", "A.8.8", 0.9, "Technical vulnerability in a managed component"),
            _MappingDraft("pci-dss", "6.3.3", 0.85, "Known vulnerability present in a system component"),
        ]
        # Any dependency vulnerability also means we should be identifying it.
        mappings.append(_MappingDraft("pci-dss", "6.3.1", 0.8, "Vulnerability identification obligation"))

    # ── Rule 2: All dependency/container findings → system monitoring ────────
    # Even medium/low severity implies the detection machinery must be in place.
    if scanner_type in ("dependencies", "containers"):
        mappings.append(_MappingDraft("soc2", "CC7.1", 0.75, "Continuous vulnerability monitoring required"))

    # ── Rule 3: Exposed secrets ───────────────────────────────────────────────
    # Credential exposure directly violates access-control and cryptography
    # controls.
    if scanner_type == "secrets":
        mappings += [
            _MappingDraft("soc2", "CC6.1", 0.95, "Credential exposure undermines logical access controls"),
            _MappingDraft("iso27001", "A.9.4", 0.95, "Access credential leaked in source or config"),
            _MappingDraft("pci-dss", "8.3.6", 0.9, "Sensitive credential exposed; cryptographic protection absent"),
        ]

    # ── Rule 4: SAST findings touching sensitive data ────────────────────────
    if scanner_type in ("sast", "code_scanning") and md.get("handles_sensitive_data"):
        mappings += [
            _MappingDraft("soc2", "CC6.7", 0.8, "Application handles sensitive data without adequate restriction"),
            _MappingDraft("pci-dss", "6.2.4", 0.8, "Insecure code pattern handling sensitive data"),
        ]

    # ── Rule 5: Public-facing surface ────────────────────────────────────────
    if md.get("is_public_facing"):
        mappings.append(
            _MappingDraft("soc2", "CC6.6", 0.8, "Public-facing surface is insufficiently hardened"),
        )
        # Public-facing + high severity is also a PCI concern
        if high_impact:
            mappings.append(
                _MappingDraft("pci-dss", "11.3.1", 0.8, "High-severity vulnerability on a public-facing system"),
            )

    # ── Rule 6: IaC / configuration drift ────────────────────────────────────
    if scanner_type in ("iac", "cloud"):
        mappings += [
            _MappingDraft("iso27001", "A.8.9", 0.85, "Infrastructure misconfiguration violates configuration management"),
            _MappingDraft("soc2", "CC6.6", 0.8, "Infrastructure hardening gap"),
        ]
        if md.get("is_public_facing") or high_impact:
            mappings.append(
                _MappingDraft("iso27001", "A.5.23", 0.75, "Cloud service configuration control weakness"),
            )

    # ── Rule 7: All high/critical findings → incident response readiness ─────
    if high_impact:
        mappings.append(
            _MappingDraft("soc2", "CC7.2", 0.7, "High-impact finding requires monitored incident response process"),
        )

    # Deduplicate by (framework, control_id) — keep highest confidence entry.
    seen: dict[tuple[str, str], _MappingDraft] = {}
    for m in mappings:
        key = (m.framework, m.control_id)
        if key not in seen or m.confidence > seen[key].confidence:
            seen[key] = m

    return list(seen.values())


def map_chain(
    *,
    chain_type: str,
    severity: str,
) -> list[_MappingDraft]:
    """Return control mapping drafts for an attack chain.

    Chains are multi-step paths, so we apply a broader set of controls and
    use higher confidence for access-control and incident-response controls.
    """
    mappings: list[_MappingDraft] = []
    sev = severity.lower()
    high_impact = sev in ("critical", "high")

    # Multi-step attack paths always involve some access-control concern.
    mappings += [
        _MappingDraft("soc2", "CC6.1", 0.85, "Attack chain involves chained access or privilege escalation"),
        _MappingDraft("soc2", "CC7.2", 0.9, "Attack chain requires coordinated incident response"),
    ]

    if high_impact:
        mappings += [
            _MappingDraft("iso27001", "A.8.8", 0.85, "Critical chain exploiting known technical vulnerabilities"),
            _MappingDraft("pci-dss", "11.3.1", 0.8, "Critical chain must be addressed within vulnerability scan cadence"),
        ]

    if "secret" in chain_type.lower() or "credential" in chain_type.lower():
        mappings += [
            _MappingDraft("iso27001", "A.9.4", 0.9, "Chain originates from or exploits credential exposure"),
            _MappingDraft("pci-dss", "8.3.6", 0.85, "Chain involves credential or cryptographic material exposure"),
        ]

    if "injection" in chain_type.lower() or "rce" in chain_type.lower():
        mappings.append(
            _MappingDraft("pci-dss", "6.2.4", 0.85, "Chain includes code injection or remote execution vector"),
        )

    # Deduplicate
    seen: dict[tuple[str, str], _MappingDraft] = {}
    for m in mappings:
        key = (m.framework, m.control_id)
        if key not in seen or m.confidence > seen[key].confidence:
            seen[key] = m

    return list(seen.values())
