"""SQLAlchemy ORM models for all application tables."""
from __future__ import annotations

from datetime import datetime, timezone

import sqlalchemy as sa
from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


# ── Settings & Config ────────────────────────────────────────────────────────


class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(255), primary_key=True)
    username: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    email: Mapped[str] = mapped_column(String(255), default="")
    password_hash: Mapped[str] = mapped_column(String(255), default="")
    role: Mapped[str] = mapped_column(String(50), default="viewer")
    role_id: Mapped[str | None] = mapped_column(String(255), ForeignKey("roles.id", ondelete="SET NULL"), nullable=True)
    status: Mapped[str] = mapped_column(String(50), default="active")
    password_reset_required: Mapped[bool] = mapped_column(Boolean, default=False)
    totp_secret: Mapped[str | None] = mapped_column(String(255), nullable=True)
    totp_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    avatar_url: Mapped[str | None] = mapped_column(Text, nullable=True)
    session_version: Mapped[int] = mapped_column(Integer, default=1)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class Role(Base):
    __tablename__ = "roles"

    id: Mapped[str] = mapped_column(String(255), primary_key=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="")
    permissions: Mapped[dict] = mapped_column(JSONB, default=dict)
    protected: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Team(Base):
    __tablename__ = "teams"

    id: Mapped[str] = mapped_column(String(255), primary_key=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="")
    source: Mapped[str] = mapped_column(String(50), default="manual")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    members: Mapped[list[TeamMember]] = relationship(back_populates="team", cascade="all, delete-orphan")
    repositories: Mapped[list[TeamRepository]] = relationship(back_populates="team", cascade="all, delete-orphan")
    container_images: Mapped[list[TeamContainerImage]] = relationship(back_populates="team", cascade="all, delete-orphan")


class TeamMember(Base):
    __tablename__ = "team_members"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    team_id: Mapped[str] = mapped_column(String(255), ForeignKey("teams.id", ondelete="CASCADE"), nullable=False)
    user_id: Mapped[str] = mapped_column(String(255), nullable=False)
    source: Mapped[str] = mapped_column(String(50), default="manual")
    added_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    team: Mapped[Team] = relationship(back_populates="members")

    __table_args__ = (
        sa.UniqueConstraint("team_id", "user_id", name="uq_team_member_team_user"),
    )


class TeamRepository(Base):
    __tablename__ = "team_repositories"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    team_id: Mapped[str] = mapped_column(String(255), ForeignKey("teams.id", ondelete="CASCADE"), nullable=False)
    org: Mapped[str] = mapped_column(String(255), nullable=False)
    repo: Mapped[str] = mapped_column(String(255), nullable=False)
    source: Mapped[str] = mapped_column(String(50), default="manual")

    team: Mapped[Team] = relationship(back_populates="repositories")

    __table_args__ = (
        sa.UniqueConstraint("team_id", "org", "repo", name="uq_team_repo_team_org_repo"),
    )


class TeamContainerImage(Base):
    __tablename__ = "team_container_images"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    team_id: Mapped[str] = mapped_column(String(255), ForeignKey("teams.id", ondelete="CASCADE"), nullable=False)
    org: Mapped[str] = mapped_column(String(255), default="")
    image: Mapped[str] = mapped_column(String(512), nullable=False)
    source: Mapped[str] = mapped_column(String(50), default="manual")

    team: Mapped[Team] = relationship(back_populates="container_images")

    __table_args__ = (
        sa.UniqueConstraint("team_id", "org", "image", name="uq_team_image_team_org_image"),
    )


class DirectGrant(Base):
    __tablename__ = "direct_grants"

    id: Mapped[str] = mapped_column(String(255), primary_key=True)
    user_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    org: Mapped[str] = mapped_column(String(255), default="")
    resource_type: Mapped[str] = mapped_column(String(50), nullable=False)
    resource_name: Mapped[str] = mapped_column(String(255), nullable=False)
    source: Mapped[str] = mapped_column(String(50), default="manual-direct")
    granted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class SourceConnection(Base):
    __tablename__ = "source_connections"

    id: Mapped[str] = mapped_column(String(255), primary_key=True)
    category: Mapped[str] = mapped_column(String(50), nullable=False)
    source_type: Mapped[str] = mapped_column(String(50), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    auth: Mapped[dict] = mapped_column(JSONB, default=dict)
    scan_scope: Mapped[str] = mapped_column(String(50), default="all")
    excluded_items: Mapped[list] = mapped_column(JSONB, default=list)
    sync_schedule: Mapped[str] = mapped_column(String(50), default="6h")
    status: Mapped[str] = mapped_column(String(50), default="not-synced")
    status_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    discovered_items: Mapped[list | None] = mapped_column(JSONB, nullable=True)
    discovered_item_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    last_synced_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    next_sync_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class AppConfig(Base):
    __tablename__ = "app_config"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, default=1)
    config: Mapped[dict] = mapped_column(JSONB, default=dict)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class License(Base):
    __tablename__ = "license"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, default=1)
    key_data: Mapped[str] = mapped_column(Text, default="")
    activated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class Runner(Base):
    __tablename__ = "runners"

    id: Mapped[str] = mapped_column(String(255), primary_key=True)
    name: Mapped[str] = mapped_column(String(255), default="")
    status: Mapped[str] = mapped_column(String(50), default="pending")
    os: Mapped[str] = mapped_column(String(50), default="")
    arch: Mapped[str] = mapped_column(String(50), default="")
    auth_token_hash: Mapped[str] = mapped_column(String(255), default="")
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_heartbeat: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    # --- Metric columns ---
    max_concurrent: Mapped[int] = mapped_column(Integer, default=2)
    cpu_percent: Mapped[float | None] = mapped_column(Float, nullable=True)
    memory_used_gb: Mapped[float | None] = mapped_column(Float, nullable=True)
    memory_total_gb: Mapped[float | None] = mapped_column(Float, nullable=True)
    disk_used_gb: Mapped[float | None] = mapped_column(Float, nullable=True)
    disk_total_gb: Mapped[float | None] = mapped_column(Float, nullable=True)
    cores: Mapped[int | None] = mapped_column(Integer, nullable=True)
    active_containers: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    scanner_images: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    jobs_completed: Mapped[int] = mapped_column(Integer, default=0)


class RunnerToken(Base):
    __tablename__ = "runner_tokens"

    token_hash: Mapped[str] = mapped_column(String(255), primary_key=True)
    runner_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    status: Mapped[str] = mapped_column(String(50), default="pending")
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class RunnerJob(Base):
    __tablename__ = "runner_jobs"

    id: Mapped[str] = mapped_column(String(255), primary_key=True)
    runner_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    job_type: Mapped[str] = mapped_column(String(50), default="")
    org: Mapped[str] = mapped_column(String(255), default="")
    run_id: Mapped[str] = mapped_column(String(255), default="")
    status: Mapped[str] = mapped_column(String(50), default="pending")
    docker_image: Mapped[str] = mapped_column(String(512), default="")
    env_vars: Mapped[dict] = mapped_column(JSONB, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        sa.Index("ix_runner_job_status_created", "status", "created_at"),
        sa.Index("ix_runner_job_runner_created", "runner_id", "created_at"),
    )


class RunnerHeartbeat(Base):
    __tablename__ = "runner_heartbeats"

    id: Mapped[str] = mapped_column(String(255), primary_key=True)
    runner_id: Mapped[str] = mapped_column(String(255), nullable=False)
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    cpu_percent: Mapped[float | None] = mapped_column(Float, nullable=True)
    memory_used_gb: Mapped[float | None] = mapped_column(Float, nullable=True)

    __table_args__ = (
        sa.Index("ix_heartbeat_runner_received", "runner_id", "received_at"),
    )


class Notification(Base):
    __tablename__ = "notifications"

    id: Mapped[str] = mapped_column(String(255), primary_key=True)
    user_id: Mapped[str] = mapped_column(String(255), nullable=False)
    type: Mapped[str] = mapped_column(String(50), default="")
    category: Mapped[str] = mapped_column(String(50), default="")
    severity: Mapped[str] = mapped_column(String(50), default="info")
    title: Mapped[str] = mapped_column(String(255), default="")
    message: Mapped[str] = mapped_column(Text, default="")
    metadata_json: Mapped[dict | None] = mapped_column("metadata", JSONB, nullable=True)
    link: Mapped[str | None] = mapped_column(String(512), nullable=True)
    read: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    __table_args__ = (
        sa.Index("ix_notification_user_read_created", "user_id", "read", "created_at"),
    )


class AuditEvent(Base):
    __tablename__ = "audit_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    action: Mapped[str] = mapped_column(String(50), nullable=False)
    actor_user_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    actor_username: Mapped[str | None] = mapped_column(String(255), nullable=True)
    target: Mapped[str | None] = mapped_column(String(512), nullable=True)
    metadata_json: Mapped[dict | None] = mapped_column("metadata", JSONB, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    __table_args__ = (
        sa.Index("ix_audit_event_created", "created_at"),
    )


# ── Scan Data ─────────────────────────────────────────────────────────────────


class ScanRun(Base):
    __tablename__ = "scan_runs"

    id: Mapped[str] = mapped_column(String(255), primary_key=True)
    tool: Mapped[str] = mapped_column(String(30), nullable=False)
    org: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[str] = mapped_column(String(50), default="queued")
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    progress: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    metadata_json: Mapped[dict | None] = mapped_column("metadata", JSONB, nullable=True)

    __table_args__ = (
        sa.Index("ix_scanrun_tool_status", "tool", "status"),
        sa.Index("ix_scanrun_tool_org_status", "tool", "org", "status"),
        sa.Index("ix_scanrun_started_at", "started_at"),
    )


class ScanCheckpoint(Base):
    __tablename__ = "scan_checkpoints"

    tool: Mapped[str] = mapped_column(String(30), primary_key=True, default="secrets")
    org: Mapped[str] = mapped_column(String(255), primary_key=True)
    repo: Mapped[str] = mapped_column(String(255), primary_key=True)
    last_commit_sha: Mapped[str] = mapped_column(String(255), default="")
    last_commit_date: Mapped[str] = mapped_column(String(50), default="")


class Finding(Base):
    """Unified finding row — one per finding across all scanners."""
    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    tool: Mapped[str] = mapped_column(String(30), nullable=False, index=True)
    org: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    repo: Mapped[str | None] = mapped_column(String(255), nullable=True)
    identity_key: Mapped[str] = mapped_column(String(512), nullable=False)
    state: Mapped[str] = mapped_column(String(20), nullable=False, default="open")
    review_status: Mapped[str | None] = mapped_column(String(20), nullable=True)
    severity: Mapped[str | None] = mapped_column(String(20), nullable=True)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    fixed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    detail: Mapped[dict] = mapped_column(JSONB, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    __table_args__ = (
        sa.UniqueConstraint("tool", "org", "identity_key", name="uq_finding_tool_org_key"),
        sa.Index("ix_finding_tool_org_state", "tool", "org", "state"),
        sa.Index("ix_finding_tool_org_severity", "tool", "org", "severity"),
        sa.Index("ix_finding_tool_org_repo", "tool", "org", "repo"),
    )


class Sbom(Base):
    """SBOM metadata per repo — blobs stored in MinIO (sboms bucket)."""
    __tablename__ = "sboms"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    org: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    repo: Mapped[str] = mapped_column(String(255), nullable=False)
    commit_sha: Mapped[str | None] = mapped_column(String(255), nullable=True)
    s3_key: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    scanned_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    run_id: Mapped[str] = mapped_column(String(100), nullable=False)

    __table_args__ = (
        sa.UniqueConstraint("org", "repo", name="uq_sbom_org_repo"),
    )


class SbomComponent(Base):
    __tablename__ = "sbom_components"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    org: Mapped[str] = mapped_column(String(255))
    repo: Mapped[str] = mapped_column(String(255))
    purl: Mapped[str] = mapped_column(String(512))
    name: Mapped[str] = mapped_column(String(255))
    version: Mapped[str] = mapped_column(String(512))
    ecosystem: Mapped[str] = mapped_column(String(100))
    source_tool: Mapped[str | None] = mapped_column(String(50), nullable=True)
    is_direct: Mapped[bool] = mapped_column(Boolean, default=True)
    scanned_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    __table_args__ = (
        sa.Index("idx_sbom_components_name", "org", "name", "ecosystem"),
        sa.Index("idx_sbom_components_purl", "org", "purl"),
        sa.UniqueConstraint("org", "repo", "purl", name="uq_sbom_components_org_repo_purl"),
    )


class Decision(Base):
    """Human action on a finding — dismiss only. Reopen = delete row."""
    __tablename__ = "decisions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    tool: Mapped[str] = mapped_column(String(30), nullable=False)
    org: Mapped[str] = mapped_column(String(255), nullable=False)
    identity_key: Mapped[str] = mapped_column(String(512), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False)
    reason: Mapped[str | None] = mapped_column(String(100), nullable=True)
    comment: Mapped[str | None] = mapped_column(Text, nullable=True)
    decided_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    decided_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    __table_args__ = (
        sa.UniqueConstraint("tool", "org", "identity_key", name="uq_decision_tool_org_key"),
        sa.Index("ix_decision_tool_org", "tool", "org"),
    )


class FindingEvent(Base):
    """Append-only audit trail for finding state changes."""
    __tablename__ = "finding_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    finding_id: Mapped[int] = mapped_column(Integer, ForeignKey("findings.id"), nullable=False)
    tool: Mapped[str] = mapped_column(String(30), nullable=False)
    org: Mapped[str] = mapped_column(String(255), nullable=False)
    identity_key: Mapped[str] = mapped_column(String(512), nullable=False)
    from_state: Mapped[str | None] = mapped_column(String(20), nullable=True)
    to_state: Mapped[str] = mapped_column(String(20), nullable=False)
    triggered_by: Mapped[str] = mapped_column(String(20), nullable=False)
    actor: Mapped[str | None] = mapped_column(String(255), nullable=True)
    metadata_json: Mapped[dict | None] = mapped_column("metadata", JSONB, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    __table_args__ = (
        sa.Index("ix_finding_event_finding_id", "finding_id"),
        sa.Index("ix_finding_event_tool_org", "tool", "org"),
    )
