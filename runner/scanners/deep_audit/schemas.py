"""Response schemas for the deep-audit reasoning engine.

These are lens-agnostic: every lens (authz first, SSRF/business-logic/... later)
produces the same finding shape, so the engine, ingest, and UI are shared. A
lens only supplies file selection and the hunter/skeptic prompts.
"""
from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

_VALID_SEVERITIES = ("low", "medium", "high", "critical")


class AuditEvidence(BaseModel):
    """A cited code location. Reuses the source/sink/gate vocabulary the finding
    drawer already renders — source: where attacker input enters; sink: the
    sensitive operation; gate: the authorization check (present or missing)."""

    model_config = ConfigDict(extra="ignore")

    kind: str = "sink"
    file: str = ""
    line: int = 0
    snippet: str = ""


class AuditFinding(BaseModel):
    """One candidate vulnerability the hunter proposes for a lens."""

    model_config = ConfigDict(extra="ignore")

    title: str
    # The endpoint or handler the finding is about, e.g. "POST /api/v1/x/{id}".
    endpoint: str = ""
    file: str
    line: int = Field(default=0, ge=0)
    severity: str = "high"
    # Lens-specific weakness discriminator, e.g. "missing_authorization".
    weakness: str = ""
    # One-paragraph narrative; cites evidence inline as [R1], [R2], ...
    exploit_chain: str = ""
    evidence: list[AuditEvidence] = Field(default_factory=list)
    # Descriptive reproduction outline (steps, not a weaponised payload).
    reproduction: str = ""
    # Concrete remediation — a unified-diff patch when the fix is small.
    fix: str = ""

    def norm_severity(self) -> str:
        s = (self.severity or "high").lower()
        return s if s in _VALID_SEVERITIES else "high"


class AuditHunterResponse(BaseModel):
    """The hunter's per-file output: zero or more candidate findings."""

    model_config = ConfigDict(extra="ignore")

    findings: list[AuditFinding] = Field(default_factory=list)


class AuditSkepticResponse(BaseModel):
    """The skeptic's refutation attempt for a single candidate finding."""

    model_config = ConfigDict(extra="ignore")

    # True when a real compensating control neutralises the finding.
    refuted: bool = False
    reason: str = ""
    # file:line + snippet of the gate/scope that refutes it, when found.
    compensating_control: str = ""
