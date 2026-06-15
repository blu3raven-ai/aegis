"""ORM models and Pydantic schemas for compliance framework mapping."""
from __future__ import annotations

from datetime import datetime, timezone

import sqlalchemy as sa
from pydantic import BaseModel, ConfigDict
from sqlalchemy import Boolean, Float, String, Text
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


class ComplianceControlMapping(Base):
    """Finding-to-control mapping row."""
    __tablename__ = "compliance_control_mappings"

    id: Mapped[int] = mapped_column(sa.BigInteger, primary_key=True, autoincrement=True)
    finding_id: Mapped[int | None] = mapped_column(sa.BigInteger, nullable=True)
    framework: Mapped[str] = mapped_column(String(64), nullable=False)
    control_id: Mapped[str] = mapped_column(String(64), nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    rationale: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        sa.TIMESTAMP(timezone=True), nullable=False, default=_utcnow
    )

    __table_args__ = (
        sa.Index('ix_compliance_finding', 'finding_id'),
        sa.Index('ix_compliance_framework_control', 'framework', 'control_id'),
    )


# ---------------------------------------------------------------------------
# Pydantic schemas
# ---------------------------------------------------------------------------


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


class ControlUpdate(BaseModel):
    title: str | None = None
    description: str | None = None
    category: str | None = None
