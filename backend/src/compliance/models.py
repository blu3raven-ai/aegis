"""ORM models and Pydantic schemas for compliance framework mapping."""
from __future__ import annotations

from datetime import date, datetime, timezone

import sqlalchemy as sa
from pydantic import BaseModel, ConfigDict
from sqlalchemy import Boolean, Date, Float, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from src.db.models import Base


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Framework(Base):
    """Compliance framework registry — both bundled and custom.

    Bundled frameworks (is_custom=false) are seeded by migration and cannot be
    deleted. Custom frameworks are owned by their creator and tracked via
    created_by_user_id + created_at.
    """
    __tablename__ = "frameworks"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    label: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    is_custom: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_by_user_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        sa.TIMESTAMP(timezone=True), nullable=False, default=_utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        sa.TIMESTAMP(timezone=True), nullable=False, default=_utcnow, onupdate=_utcnow
    )


class FrameworkControl(Base):
    """Static reference table of compliance controls."""
    __tablename__ = "framework_controls"

    id: Mapped[int] = mapped_column(sa.BigInteger, primary_key=True, autoincrement=True)
    framework: Mapped[str] = mapped_column(
        String(64),
        sa.ForeignKey("frameworks.id", ondelete="CASCADE"),
        nullable=False,
    )
    control_id: Mapped[str] = mapped_column(String(64), nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    category: Mapped[str | None] = mapped_column(String(128), nullable=True)
    is_custom: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_by_user_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        sa.TIMESTAMP(timezone=True), nullable=False, default=_utcnow
    )

    __table_args__ = (
        sa.UniqueConstraint('framework', 'control_id', name='uq_framework_control'),
        sa.Index('ix_framework_controls_fw', 'framework'),
    )


ASSESSMENT_STATUSES = frozenset(
    {"compliant", "non_compliant", "in_progress", "not_applicable"}
)


class ComplianceControlAssessment(Base):
    """Analyst attestation that overrides the finding-derived control status.

    Auto-mapping answers "are there open findings against this control"; an
    assessment answers "has a human reviewed it and what's the evidence" — the
    layer auditors actually sign off on. One row per (framework, control_id);
    absence means the control falls back to its derived status.
    """
    __tablename__ = "compliance_control_assessments"

    id: Mapped[int] = mapped_column(sa.BigInteger, primary_key=True, autoincrement=True)
    framework: Mapped[str] = mapped_column(String(64), nullable=False)
    control_id: Mapped[str] = mapped_column(String(64), nullable=False)
    # One of ASSESSMENT_STATUSES, or NULL to fall back to the derived status
    # while still retaining the evidence note.
    status: Mapped[str | None] = mapped_column(String(32), nullable=True)
    evidence_note: Mapped[str | None] = mapped_column(Text, nullable=True)
    evidence_url: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    # Remediation overlay: who owns closing the gap, and by when.
    owner_user_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    due_date: Mapped[date | None] = mapped_column(Date, nullable=True)
    assessed_by_user_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    assessed_at: Mapped[datetime] = mapped_column(
        sa.TIMESTAMP(timezone=True), nullable=False, default=_utcnow, onupdate=_utcnow
    )

    __table_args__ = (
        sa.UniqueConstraint("framework", "control_id", name="uq_control_assessment"),
        sa.Index("ix_control_assessments_fw", "framework"),
    )


class ComplianceControlMapping(Base):
    """Finding-to-control mapping row."""
    __tablename__ = "compliance_control_mappings"

    id: Mapped[int] = mapped_column(sa.BigInteger, primary_key=True, autoincrement=True)
    finding_id: Mapped[int | None] = mapped_column(sa.BigInteger, nullable=True)
    framework: Mapped[str] = mapped_column(String(64), nullable=False)
    control_id: Mapped[str] = mapped_column(String(64), nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    rationale: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Analyst-created mapping the rule-based mapper missed. Distinguished from
    # auto-mappings so the UI can label it and re-scans never touch it.
    manual: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default=sa.text("false")
    )
    # Analyst override: a suppressed mapping is a false positive — kept for the
    # audit trail but excluded from a control's status and finding counts. The
    # auto-mapper is idempotent (skips existing rows), so suppression survives
    # re-scans.
    suppressed: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default=sa.text("false")
    )
    suppressed_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    suppressed_by_user_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    suppressed_at: Mapped[datetime | None] = mapped_column(
        sa.TIMESTAMP(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        sa.TIMESTAMP(timezone=True), nullable=False, default=_utcnow
    )

    __table_args__ = (
        sa.Index('ix_compliance_finding', 'finding_id'),
        sa.Index('ix_compliance_framework_control', 'framework', 'control_id'),
        # One mapping row per finding↔control pair — the auto-mapper and the
        # manual-map path both rely on this; it makes check-then-insert races
        # fail loudly instead of silently double-counting a control.
        sa.UniqueConstraint(
            'finding_id', 'framework', 'control_id',
            name='uq_compliance_mapping_finding_control',
        ),
    )


# Pydantic schemas


class FrameworkControlSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    framework: str
    control_id: str
    title: str
    description: str | None
    category: str | None


class ComplianceControlMappingSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    finding_id: int | None
    framework: str
    control_id: str
    confidence: float
    rationale: str | None
    created_at: datetime


class ControlSummaryItem(BaseModel):
    """Aggregated view of one control: how many findings map to it."""
    framework: str
    control_id: str
    title: str
    category: str | None
    finding_count: int
    highest_severity: str | None
    # Manual attestation overlay — null when the control has never been assessed.
    manual_status: str | None = None
    evidence_note: str | None = None
    evidence_url: str | None = None
    assessed_by: str | None = None
    assessed_at: str | None = None
    # Remediation overlay.
    owner_user_id: str | None = None
    owner_label: str | None = None  # resolved username for display
    due_date: str | None = None  # ISO date
    overdue: bool = False  # due_date in the past and the control isn't met


class ControlAssessmentUpsert(BaseModel):
    """Body for setting a control's manual attestation. `status` of "auto" (or
    null) clears the override while keeping any evidence note."""
    status: str | None = None
    evidence_note: str | None = None
    evidence_url: str | None = None
    owner_user_id: str | None = None
    due_date: str | None = None  # ISO date (YYYY-MM-DD), or null/"" to clear


class ControlAssessmentResponse(BaseModel):
    framework: str
    control_id: str
    status: str | None
    evidence_note: str | None
    evidence_url: str | None
    owner_user_id: str | None
    due_date: str | None
    assessed_by: str | None
    assessed_at: str | None


class FindingBrief(BaseModel):
    """Minimal finding representation returned inside compliance endpoints."""
    id: int
    tool: str
    org: str
    repo: str | None
    severity: str | None
    state: str
    identity_key: str
    confidence: float
    rationale: str | None
    mapping_id: int
    suppressed: bool = False
    manual: bool = False


class FrameworkResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    label: str
    description: str | None
    is_custom: bool
    created_by_user_id: str | None
    created_at: datetime
    updated_at: datetime


class FrameworkCreate(BaseModel):
    id: str
    label: str
    description: str | None = None


class FrameworkUpdate(BaseModel):
    label: str | None = None
    description: str | None = None


class ControlResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    framework: str
    control_id: str
    title: str
    description: str | None
    category: str | None
    is_custom: bool
    created_by_user_id: str | None
    created_at: datetime


class ControlCreate(BaseModel):
    control_id: str
    title: str
    description: str | None = None
    category: str | None = None


class FrameworkWithControlsCreate(BaseModel):
    """Create a framework and its initial controls in one atomic request."""
    id: str
    label: str
    description: str | None = None
    controls: list[ControlCreate] = []


class ControlUpdate(BaseModel):
    title: str | None = None
    description: str | None = None
    category: str | None = None


# Read envelopes for the GET endpoints. The shapes mirror the existing JSON the
# handlers already return — kept distinct from the CRUD models above so that
# adding/removing internal fields (e.g. created_by_user_id) on a write response
# doesn't accidentally change what reads expose.


class ComplianceFrameworkBrief(BaseModel):
    """Lightweight {id, label} pair used by the catalog list."""
    id: str
    label: str


class FrameworksList(BaseModel):
    frameworks: list[ComplianceFrameworkBrief]


class ControlReadItem(BaseModel):
    id: int
    framework: str
    control_id: str
    title: str
    description: str | None
    category: str | None


class FrameworkControlsList(BaseModel):
    controls: list[ControlReadItem]


class FrameworkSummaryResponse(BaseModel):
    framework: str
    label: str
    controls: list[ControlSummaryItem]


class ComplianceFindingBriefResponse(BaseModel):
    id: int
    tool: str
    org: str
    repo: str | None
    severity: str | None
    state: str
    identity_key: str
    confidence: float
    rationale: str | None
    mapping_id: int
    suppressed: bool = False
    manual: bool = False


class MappingSuppressRequest(BaseModel):
    """Body for suppressing/restoring an auto-generated finding→control mapping."""
    suppressed: bool
    reason: str | None = None


class MappingCreateRequest(BaseModel):
    """Body for manually mapping a finding to a control."""
    finding_id: int


class MappingCreatedResponse(BaseModel):
    """Result of a manual-map request. ``created`` is False when the finding was
    already actively mapped (idempotent no-op)."""
    mapping_id: int
    finding_id: int
    created: bool


class MappableFindingItem(BaseModel):
    """A finding offered in the manual-map picker — open, in scope, not yet
    mapped to the target control."""
    id: int
    tool: str
    title: str | None
    severity: str | None
    org: str
    repo: str | None
    identity_key: str


class MappableFindingsResponse(BaseModel):
    findings: list[MappableFindingItem]


class ControlFindingsResponse(BaseModel):
    framework: str
    control_id: str
    findings: list[ComplianceFindingBriefResponse]


class ControlMappingResponse(BaseModel):
    framework: str
    control_id: str
    title: str
    confidence: float
    rationale: str | None


class FindingControlsResponse(BaseModel):
    finding_id: int
    mappings: list[ControlMappingResponse]
