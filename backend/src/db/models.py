"""SQLAlchemy ORM models for all application tables."""
from __future__ import annotations

from datetime import date, datetime, timezone

import sqlalchemy as sa
from sqlalchemy import BigInteger, Boolean, Date, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import ARRAY, JSONB
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
    # Legacy columns kept for backward compat with settings/audit.py
    action: Mapped[str] = mapped_column(String(128), nullable=False)
    actor_user_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    actor_username: Mapped[str | None] = mapped_column(String(255), nullable=True)
    target: Mapped[str | None] = mapped_column(String(512), nullable=True)
    metadata_json: Mapped[dict | None] = mapped_column("metadata", JSONB, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    # Extended compliance columns added in Phase 19
    org_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    actor_email: Mapped[str | None] = mapped_column(String(255), nullable=True)
    actor_role: Mapped[str | None] = mapped_column(String(64), nullable=True)
    resource_type: Mapped[str | None] = mapped_column(String(64), nullable=True)
    resource_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    request_method: Mapped[str | None] = mapped_column(String(8), nullable=True)
    request_path: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    request_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String(512), nullable=True)
    changes: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    status_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    occurred_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), default=utcnow)

    __table_args__ = (
        sa.Index("ix_audit_event_created", "created_at"),
        sa.Index("ix_audit_org_occurred", "org_id", "occurred_at"),
        sa.Index("ix_audit_actor_id", "actor_user_id", "occurred_at"),
        sa.Index("ix_audit_action_occ", "action", "occurred_at"),
        sa.Index("ix_audit_resource", "resource_type", "resource_id"),
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
    # Commit attribution (§5.6 v1 carve-out from type 4 temporal correlation).
    # Populated at ingest time from git blame; stays NULL when checkout is unavailable.
    introduced_by_commit_sha: Mapped[str | None] = mapped_column(String(64), nullable=True)
    introduced_by_author: Mapped[str | None] = mapped_column(String(255), nullable=True)
    introduced_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    introduced_by_pr_url: Mapped[str | None] = mapped_column(String(512), nullable=True)

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


class CacheEntry(Base):
    """Generic per-tool scan cache row — blobs stored in MinIO."""
    __tablename__ = "cache_entries"

    id: Mapped[int] = mapped_column(sa.BigInteger, primary_key=True, autoincrement=True)
    cache_type: Mapped[str] = mapped_column(String(64), nullable=False)
    cache_key: Mapped[str] = mapped_column(String(512), nullable=False)
    content_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    tool_version: Mapped[str] = mapped_column(String(64), nullable=False)
    rule_pack_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_used_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    blob_pointer: Mapped[str | None] = mapped_column(String(1024), nullable=True)

    __table_args__ = (
        sa.UniqueConstraint("cache_type", "cache_key", name="uq_cache_type_key"),
        sa.Index("ix_cache_entries_last_used_at", "last_used_at"),
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


class VerifiedSecret(Base):
    """Verified-secret cache: avoids re-calling live verifiers within TTL window."""
    __tablename__ = "verified_secrets"

    id: Mapped[int] = mapped_column(sa.BigInteger, primary_key=True, autoincrement=True)
    detector_id: Mapped[str] = mapped_column(String(128), nullable=False)
    secret_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    verified_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    ttl_until: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    __table_args__ = (
        sa.UniqueConstraint("detector_id", "secret_hash", name="uq_detector_secret"),
        sa.Index("ix_verified_secrets_ttl", "ttl_until"),
    )


class Chain(Base):
    """Attack chain — groups related findings into a multi-step vulnerability path."""
    __tablename__ = "chains"

    id: Mapped[str] = mapped_column(String(26), primary_key=True)  # ULID
    org_id: Mapped[str] = mapped_column(String(255), nullable=False)
    chain_type: Mapped[str] = mapped_column(String(64), nullable=False)
    severity: Mapped[str] = mapped_column(String(20), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="open")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )
    ai_explanation_id: Mapped[str | None] = mapped_column(String(255), nullable=True)

    edges: Mapped[list["ChainEdge"]] = relationship(
        back_populates="chain", cascade="all, delete-orphan"
    )

    __table_args__ = (
        sa.Index("ix_chains_org_id", "org_id"),
        sa.Index("ix_chains_org_severity", "org_id", "severity"),
        sa.Index("ix_chains_org_type", "org_id", "chain_type"),
        sa.Index("ix_chains_status", "status"),
    )


class ChainEdge(Base):
    """Directed edge between two findings within an attack chain."""
    __tablename__ = "chain_edges"

    id: Mapped[int] = mapped_column(sa.BigInteger, primary_key=True, autoincrement=True)
    chain_id: Mapped[str] = mapped_column(
        String(26), ForeignKey("chains.id", ondelete="CASCADE"), nullable=False
    )
    source_finding_id: Mapped[int] = mapped_column(Integer, nullable=False)
    target_finding_id: Mapped[int] = mapped_column(Integer, nullable=False)
    edge_type: Mapped[str] = mapped_column(String(64), nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    provenance_rule: Mapped[str] = mapped_column(String(128), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    chain: Mapped["Chain"] = relationship(back_populates="edges")

    __table_args__ = (
        sa.UniqueConstraint(
            "chain_id", "source_finding_id", "target_finding_id", "edge_type",
            name="uq_chain_edge_dedup",
        ),
        sa.Index("ix_chain_edges_chain_id", "chain_id"),
        sa.Index("ix_chain_edges_source", "source_finding_id"),
        sa.Index("ix_chain_edges_target", "target_finding_id"),
    )


class TemporalAggregate(Base):
    """Bucketed time-series aggregate for Phase 11 Type 4 temporal correlation.

    One row per (org, metric_type, dimension_key, bucket_start, bucket_size).
    Upserts increment `value` in place; the unique constraint enforces
    one bucket per dimension so writes are idempotent.
    """
    __tablename__ = "temporal_aggregates"

    id: Mapped[int] = mapped_column(sa.BigInteger, primary_key=True, autoincrement=True)
    org_id: Mapped[str] = mapped_column(String(255), nullable=False)
    # Identifies which metric this row tracks — e.g. 'findings_introduced', 'mttr'.
    metric_type: Mapped[str] = mapped_column(String(64), nullable=False)
    # Composite dimension string: "k1=v1|k2=v2" sorted lexicographically by key.
    dimension_key: Mapped[str] = mapped_column(String(512), nullable=False)
    bucket_start: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    # '1h' | '1d' | '1w'
    bucket_size: Mapped[str] = mapped_column(String(16), nullable=False)
    value: Mapped[float] = mapped_column(Float, nullable=False)
    # Extra context; used by MTTR to persist raw duration samples.
    # Column is named 'metadata' in the DB but uses 'extra' as the ORM attribute
    # because SQLAlchemy reserves the name 'metadata' on declarative base classes.
    extra: Mapped[dict | None] = mapped_column("metadata", JSONB, nullable=True)

    __table_args__ = (
        sa.UniqueConstraint(
            'org_id', 'metric_type', 'dimension_key', 'bucket_start', 'bucket_size',
            name='uq_temporal_aggregate_bucket',
        ),
        sa.Index('ix_temporal_org_metric_bucket', 'org_id', 'metric_type', 'bucket_start'),
    )


# ── Phase 13: External notification routing ──────────────────────────────────


class NotificationDestination(Base):
    """Outbound delivery channel configured per-org.

    destination_type is 'slack' | 'webhook' | 'email'.
    config is type-specific: webhook_url for Slack, url+secret for generic
    webhooks, to_addresses list for email.
    event_filter narrows which event types (and min severity) reach this dest.
    """
    __tablename__ = "notification_destinations"

    id: Mapped[int] = mapped_column(sa.BigInteger, primary_key=True, autoincrement=True)
    org_id: Mapped[str] = mapped_column(String(255), nullable=False)
    destination_type: Mapped[str] = mapped_column(String(32), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    config: Mapped[dict] = mapped_column(JSONB, nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    event_filter: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    deliveries: Mapped[list["NotificationDelivery"]] = relationship(
        back_populates="destination", cascade="all, delete-orphan"
    )

    __table_args__ = (
        sa.UniqueConstraint('org_id', 'name', name='uq_notif_dest_org_name'),
        sa.Index('ix_notif_dest_org_id', 'org_id'),
    )


class NotificationDelivery(Base):
    """Audit record for every dispatch attempt — one row per (destination, event).

    The unique constraint on (destination_id, event_id) prevents double-delivery
    even if the router processes the same event twice (e.g. after a crash).
    """
    __tablename__ = "notification_deliveries"

    id: Mapped[int] = mapped_column(sa.BigInteger, primary_key=True, autoincrement=True)
    destination_id: Mapped[int] = mapped_column(
        sa.BigInteger, ForeignKey("notification_destinations.id", ondelete="CASCADE"), nullable=False
    )
    event_id: Mapped[str] = mapped_column(String(64), nullable=False)
    event_type: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    payload_summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    response_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    attempted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    destination: Mapped["NotificationDestination"] = relationship(back_populates="deliveries")

    __table_args__ = (
        sa.UniqueConstraint('destination_id', 'event_id', name='uq_notif_delivery_dest_event'),
        sa.Index('ix_notif_deliveries_status', 'status', 'attempted_at'),
    )


# ── Phase 42: Notification routing rules ─────────────────────────────────────


class NotificationRule(Base):
    """Rule that maps a finding predicate tree to a notification channel.

    Rules are evaluated in ascending priority order. The first matching enabled
    rule routes the finding to its channel_id. If no rule matches, the caller
    falls back to the legacy all-destinations fanout.

    conditions JSONB holds an all/any predicate tree — see routing.py for
    evaluation semantics.
    """
    __tablename__ = "notification_rules"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    priority: Mapped[int] = mapped_column(Integer, nullable=False, default=100)
    channel_id: Mapped[int] = mapped_column(
        sa.BigInteger,
        ForeignKey("notification_destinations.id", ondelete="CASCADE"),
        nullable=False,
    )
    conditions: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)
    org_id: Mapped[str] = mapped_column(String(255), nullable=False)

    __table_args__ = (
        sa.Index('ix_notif_rules_org_id', 'org_id'),
        sa.Index('ix_notif_rules_org_priority', 'org_id', 'priority'),
    )


# ── Phase 27: Repos asset management ─────────────────────────────────────────


class Repo(Base):
    """Per-repo scan-state store — populated by Phase 2 incremental scanning.

    One row per (org, repo). `manifest_set_hash` and `last_scanned_sha` drive
    delta detection. `updated_at` reflects the most recent cache write.
    """
    __tablename__ = "repos"

    id: Mapped[int] = mapped_column(sa.BigInteger, primary_key=True, autoincrement=True)
    org: Mapped[str] = mapped_column(String(255), nullable=False)
    repo: Mapped[str] = mapped_column(String(255), nullable=False)
    manifest_set_hash: Mapped[str | None] = mapped_column(String(128), nullable=True)
    last_scanned_sha: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    __table_args__ = (
        sa.UniqueConstraint("org", "repo", name="uq_repos_org_repo"),
    )


# ── API Keys ─────────────────────────────────────────────────────────────────

class ApiKey(Base):
    """Revocable API token — token stored only as SHA-256 hash."""
    __tablename__ = "api_keys"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    org_id: Mapped[str] = mapped_column(String(255), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    # First 8 chars of the token format ("ak_live_") stored for display
    prefix: Mapped[str] = mapped_column(String(64), nullable=False)
    # Last 4 chars of the full token stored for display
    last_four: Mapped[str] = mapped_column(String(4), nullable=False)
    # SHA-256 hex digest — never exposed through any API response
    token_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    scopes: Mapped[list[str]] = mapped_column(ARRAY(Text), nullable=False, default=list)
    created_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        sa.Index("ix_api_keys_org", "org_id", "revoked_at"),
        sa.Index("ix_api_keys_prefix", "prefix"),
    )


# ── Webhook signing secrets (Phase 44) ───────────────────────────────────────

class WebhookSigningSecret(Base):
    """Per-channel HMAC signing secret with rotation history.

    Multiple rows per channel are permitted during the rotation window so
    receivers can verify against both old and new secrets simultaneously.
    The raw secret is shown once on creation and never stored.
    """
    __tablename__ = "webhook_signing_secrets"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    channel_id: Mapped[int] = mapped_column(
        BigInteger,
        ForeignKey("notification_destinations.id", ondelete="CASCADE"),
        nullable=False,
    )
    # SHA-256 hex digest — raw secret never stored beyond the response
    secret_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    # 'active' | 'rotating' | 'revoked'
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="active")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        sa.Index("ix_wss_channel_id_status", "channel_id", "status"),
        sa.Index("ix_wss_channel_id_version", "channel_id", "version"),
    )


# ── SLA ──────────────────────────────────────────────────────────────────────


class SlaPolicy(Base):
    """Per-org, per-severity remediation deadline policy."""
    __tablename__ = "sla_policies"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    org_id: Mapped[str] = mapped_column(String(255), nullable=False)
    severity: Mapped[str] = mapped_column(String(10), nullable=False)
    deadline_days: Mapped[int] = mapped_column(Integer, nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    __table_args__ = (
        sa.UniqueConstraint("org_id", "severity", name="uq_sla_policy_org_severity"),
        sa.Index("ix_sla_policies_org_id", "org_id"),
    )


class FindingSlaStatus(Base):
    """Computed SLA breach status for a finding, refreshed by the hourly recompute job."""
    __tablename__ = "finding_sla_status"

    finding_id: Mapped[int] = mapped_column(Integer, ForeignKey("findings.id", ondelete="CASCADE"), primary_key=True)
    deadline_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    breached: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    breach_age_days: Mapped[int | None] = mapped_column(Integer, nullable=True)
    computed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    __table_args__ = (
        sa.Index("ix_finding_sla_status_breached", "breached"),
    )


# ── CISA KEV Catalog ──────────────────────────────────────────────────────────


class KevEntry(Base):
    """One row per CVE in the CISA Known Exploited Vulnerabilities catalog.

    Refreshed daily via the background job in src/jobs/kev_refresh.py.
    cve_id is the natural PK because CISA guarantees uniqueness and it is the
    join key used when correlating against org findings.
    """
    __tablename__ = "kev_entries"

    cve_id: Mapped[str] = mapped_column(String(20), primary_key=True)
    vendor_project: Mapped[str | None] = mapped_column(String(120), nullable=True)
    product: Mapped[str | None] = mapped_column(String(120), nullable=True)
    vulnerability_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    date_added: Mapped[date | None] = mapped_column(Date(), nullable=True, index=True)
    short_description: Mapped[str | None] = mapped_column(Text, nullable=True)
    required_action: Mapped[str | None] = mapped_column(Text, nullable=True)
    due_date: Mapped[date | None] = mapped_column(Date(), nullable=True)
    known_ransomware_use: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    cwes: Mapped[list | None] = mapped_column(JSONB, nullable=True)
    ingested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


# ── EPSS Scores ──────────────────────────────────────────────────────────────


class EpssScore(Base):
    """One row per CVE with the latest EPSS score from FIRST.org.

    EPSS (Exploit Prediction Scoring System) publishes a daily CSV with a
    probability (0.0–1.0) that a given CVE will be exploited in the next 30
    days, plus its percentile rank against all other scored CVEs.

    Refreshed daily via src/jobs/epss_refresh.py. cve is the natural PK — the
    feed publishes one current row per CVE and we keep only the latest.
    """
    __tablename__ = "epss_scores"

    cve: Mapped[str] = mapped_column(String(20), primary_key=True)
    score: Mapped[float] = mapped_column(Float, nullable=False)
    percentile: Mapped[float] = mapped_column(Float, nullable=False)
    scored_date: Mapped[date] = mapped_column(Date(), nullable=False, index=True)
    fetched_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
