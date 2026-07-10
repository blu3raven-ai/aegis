"""SQLAlchemy ORM models for all application tables."""
from __future__ import annotations

from datetime import date, datetime, timezone

import sqlalchemy as sa
from sqlalchemy import BigInteger, Boolean, Date, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import ARRAY, INET, JSONB, UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass




class User(Base):
    __tablename__ = "users"
    __table_args__ = (
        sa.Index(
            "uq_users_sso_subject",
            "sso_subject",
            unique=True,
            postgresql_where=sa.text("sso_subject IS NOT NULL"),
        ),
    )

    id: Mapped[str] = mapped_column(String(255), primary_key=True)
    username: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    email: Mapped[str] = mapped_column(String(255), default="")
    password_hash: Mapped[str] = mapped_column(String(255), default="")
    role_id: Mapped[str | None] = mapped_column(String(255), ForeignKey("roles.id", ondelete="SET NULL"), nullable=True)
    status: Mapped[str] = mapped_column(String(50), default="active")
    password_reset_required: Mapped[bool] = mapped_column(Boolean, default=False)
    totp_secret: Mapped[str | None] = mapped_column(String(255), nullable=True)
    totp_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    avatar_url: Mapped[str | None] = mapped_column(Text, nullable=True)
    session_version: Mapped[int] = mapped_column(Integer, default=1)
    sso_subject: Mapped[str | None] = mapped_column(String(512), nullable=True)
    sso_protocol: Mapped[str | None] = mapped_column(String(16), nullable=True)
    scim_managed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, server_default=sa.false())
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class UserPreferences(Base):
    __tablename__ = "user_preferences"

    user_id: Mapped[str] = mapped_column(String(255), ForeignKey("users.id", ondelete="CASCADE"), primary_key=True)
    theme: Mapped[str] = mapped_column(String(16), default="system", nullable=False)
    timezone: Mapped[str] = mapped_column(String(64), default="UTC", nullable=False)
    notif_assignments: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    notif_mentions: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    notif_kev: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    notif_weekly_digest: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    notif_marketing: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False)


class OrgSettings(Base):
    __tablename__ = "org_settings"
    __table_args__ = (sa.CheckConstraint("id = 1", name="ck_org_settings_singleton"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=False)
    name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    logo_data_url: Mapped[str | None] = mapped_column(Text, nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False)


class SsoConfig(Base):
    __tablename__ = "sso_config"
    __table_args__ = (sa.CheckConstraint("id = 1", name="ck_sso_config_singleton"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    protocol: Mapped[str | None] = mapped_column(String(16), nullable=True)
    default_role_id: Mapped[str | None] = mapped_column(String(255), ForeignKey("roles.id", ondelete="SET NULL"), nullable=True)
    saml_metadata_url: Mapped[str | None] = mapped_column(Text, nullable=True)
    saml_metadata_xml: Mapped[str | None] = mapped_column(Text, nullable=True)
    saml_sp_private_key_enc: Mapped[str | None] = mapped_column(Text, nullable=True)
    saml_sp_certificate: Mapped[str | None] = mapped_column(Text, nullable=True)
    saml_validate_metadata_signature: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default=sa.text("false"),
    )
    oidc_discovery_url: Mapped[str | None] = mapped_column(Text, nullable=True)
    oidc_client_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    oidc_client_secret_enc: Mapped[str | None] = mapped_column(Text, nullable=True)
    oidc_scopes: Mapped[str] = mapped_column(String(255), default="openid email profile", nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False)


class ScimConfig(Base):
    __tablename__ = "scim_config"
    __table_args__ = (sa.CheckConstraint("id = 1", name="ck_scim_config_singleton"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    token_hash: Mapped[str | None] = mapped_column(String(128), nullable=True)
    default_role_id: Mapped[str | None] = mapped_column(String(255), ForeignKey("roles.id", ondelete="SET NULL"), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False)


class AuditStreamConfig(Base):
    __tablename__ = "audit_stream_config"
    __table_args__ = (sa.CheckConstraint("id = 1", name="ck_audit_stream_config_singleton"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    target_type: Mapped[str | None] = mapped_column(String(32), nullable=True)
    endpoint_url: Mapped[str | None] = mapped_column(Text, nullable=True)
    auth_token_enc: Mapped[str | None] = mapped_column(Text, nullable=True)
    last_event_id: Mapped[int] = mapped_column(BigInteger, default=0, nullable=False)
    last_success_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_error: Mapped[str | None] = mapped_column(String(500), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False)


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


class Grant(Base):
    """Unified access grant: either a user or a team may access an asset."""
    __tablename__ = "grants"

    subject_type: Mapped[str] = mapped_column(String(10), primary_key=True)
    subject_id: Mapped[str] = mapped_column(String(255), primary_key=True)
    asset_id: Mapped[str] = mapped_column(
        UUID(as_uuid=False),
        ForeignKey("assets.id", ondelete="CASCADE"),
        primary_key=True,
    )
    source: Mapped[str] = mapped_column(String(50), nullable=False, default="manual")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    __table_args__ = (
        sa.Index("ix_grants_asset_id", "asset_id"),
        sa.Index("ix_grants_subject", "subject_type", "subject_id"),
        sa.CheckConstraint("subject_type IN ('user', 'team')", name="ck_grants_subject_type"),
    )


class SourceConnection(Base):
    __tablename__ = "source_connections"

    id: Mapped[str] = mapped_column(String(255), primary_key=True)
    category: Mapped[str] = mapped_column(String(50), nullable=False)
    source_type: Mapped[str] = mapped_column(String(50), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    auth: Mapped[dict] = mapped_column(JSONB, default=dict)
    scan_scope: Mapped[str] = mapped_column(String(50), default="all")
    excluded_items: Mapped[list] = mapped_column(JSONB, default=list)
    # Explicit cherry-pick allow-list of "owner/repo" (or clone URL for public
    # sources) used when scan_scope == "selected". Empty for legacy all/exclude
    # connections.
    included_items: Mapped[list] = mapped_column(
        JSONB, nullable=False, default=list, server_default="[]"
    )
    # Which scanner job types to run for this source. Empty = all scanners
    # applicable to the category (see SCANNERS_BY_CATEGORY).
    scanners: Mapped[list] = mapped_column(JSONB, nullable=False, default=list, server_default="[]")
    # How the source was connected: any of "pat", "webhook", "cicd". Recorded
    # from the Add Source flow; a source may combine more than one.
    connection_methods: Mapped[list] = mapped_column(
        JSONB, nullable=False, default=lambda: ["pat"], server_default='["pat"]'
    )
    sync_schedule: Mapped[str] = mapped_column(String(50), default="6h")
    # Sync schedule editing mode: "preset" uses sync_schedule, "cron" uses sync_schedule_cron.
    sync_schedule_mode: Mapped[str] = mapped_column(String(10), nullable=False, default="preset", server_default="preset")
    sync_schedule_cron: Mapped[str | None] = mapped_column(String(120), nullable=True)
    # Auto-rerun of scans on a schedule (independent of sync re-discovery).
    scan_auto_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, server_default=sa.false())
    scan_schedule_mode: Mapped[str] = mapped_column(String(10), nullable=False, default="preset", server_default="preset")
    scan_schedule_preset: Mapped[str] = mapped_column(String(50), nullable=False, default="24h", server_default="24h")
    scan_schedule_cron: Mapped[str | None] = mapped_column(String(120), nullable=True)
    status: Mapped[str] = mapped_column(String(50), default="not-synced")
    status_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    discovered_items: Mapped[list | None] = mapped_column(JSONB, nullable=True)
    discovered_item_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    last_synced_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    next_sync_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)
    org_id: Mapped[str] = mapped_column(String(255), nullable=False, server_default="default")

    __table_args__ = (
        sa.CheckConstraint(
            "status IN ('connected', 'syncing', 'error', 'disconnected', 'not-synced')",
            name="ck_source_connections_status",
        ),
        sa.CheckConstraint(
            "scan_scope IN ('all', 'all-except-excluded', 'selected')",
            name="ck_source_connections_scan_scope",
        ),
        sa.CheckConstraint(
            "sync_schedule IN ('1h', '3h', '6h', '12h', '24h')",
            name="ck_source_connections_sync_schedule",
        ),
        sa.CheckConstraint(
            "scan_schedule_preset IN ('1h', '3h', '6h', '12h', '24h')",
            name="ck_source_connections_scan_schedule_preset",
        ),
        sa.CheckConstraint(
            "sync_schedule_mode IN ('preset', 'cron')",
            name="ck_source_connections_sync_schedule_mode",
        ),
        sa.CheckConstraint(
            "scan_schedule_mode IN ('preset', 'cron')",
            name="ck_source_connections_scan_schedule_mode",
        ),
    )


class WebhookEndpoint(Base):
    """Per-org webhook receiver secret for a single provider.

    Bootstrap remains via env-var (GITHUB_WEBHOOK_SECRET / etc.). A DB row
    overrides the env-var on a per-provider basis so customers can rotate
    without redeploying.
    """
    __tablename__ = "webhook_endpoints"
    __table_args__ = (
        sa.UniqueConstraint("org_id", "provider", name="uq_webhook_endpoints_org_provider"),
        sa.CheckConstraint(
            "provider IN ('github','gitlab','bitbucket','azure_devops','jenkins')",
            name="ck_webhook_endpoints_provider",
        ),
        sa.Index("ix_webhook_endpoints_provider", "provider"),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    org_id: Mapped[str] = mapped_column(String(255), nullable=False, default="default")
    provider: Mapped[str] = mapped_column(String(32), nullable=False)
    secret_enc: Mapped[str] = mapped_column(Text, nullable=False)
    last4: Mapped[str] = mapped_column(String(4), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False)
    rotated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


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
    org_id: Mapped[str | None] = mapped_column(String(255), nullable=True)

    __table_args__ = (
        sa.CheckConstraint(
            "status IN ('pending', 'pending_approval', 'approved')",
            name="ck_runners_status",
        ),
    )


class RunnerToken(Base):
    __tablename__ = "runner_tokens"

    token_hash: Mapped[str] = mapped_column(String(255), primary_key=True)
    runner_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    status: Mapped[str] = mapped_column(String(50), default="pending")
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    __table_args__ = (
        sa.CheckConstraint(
            "status IN ('pending', 'used')",
            name="ck_runner_tokens_status",
        ),
    )


class RunnerJob(Base):
    __tablename__ = "runner_jobs"

    id: Mapped[str] = mapped_column(String(255), primary_key=True)
    runner_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    job_type: Mapped[str] = mapped_column(String(50), default="")
    org: Mapped[str] = mapped_column(String(255), default="")
    run_id: Mapped[str] = mapped_column(String(255), default="")
    status: Mapped[str] = mapped_column(String(50), default="pending")
    env_vars: Mapped[dict] = mapped_column(JSONB, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        sa.Index("ix_runner_job_status_created", "status", "created_at"),
        sa.Index("ix_runner_job_runner_created", "runner_id", "created_at"),
        sa.CheckConstraint(
            "status IN ('pending', 'queued', 'assigned', 'running', 'completed', 'failed', 'cancelled')",
            name="ck_runner_jobs_status",
        ),
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
        sa.CheckConstraint(
            "severity IN ('critical', 'warning', 'success', 'error', 'info')",
            name="ck_notifications_severity",
        ),
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
    org_id: Mapped[str] = mapped_column(String(255), nullable=False, server_default="default")

    __table_args__ = (
        sa.Index("ix_audit_event_created", "created_at"),
        sa.Index("ix_audit_actor_id", "actor_user_id", "occurred_at"),
        sa.Index("ix_audit_action_occ", "action", "occurred_at"),
        sa.Index("ix_audit_resource", "resource_type", "resource_id"),
    )




class ScanRun(Base):
    __tablename__ = "scan_runs"

    id: Mapped[str] = mapped_column(String(255), primary_key=True)
    tool: Mapped[str] = mapped_column(String(30), nullable=False)
    asset_id: Mapped[str | None] = mapped_column(
        UUID(as_uuid=False),
        ForeignKey("assets.id", ondelete="RESTRICT"),
        nullable=True, index=True,
    )
    status: Mapped[str] = mapped_column(String(50), default="queued")
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    progress: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    metadata_json: Mapped[dict | None] = mapped_column("metadata", JSONB, nullable=True)
    archived: Mapped[bool] = mapped_column(sa.Boolean, nullable=False, server_default=sa.text("false"))
    archived_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    archived_by_rule_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    triggered_by: Mapped[str | None] = mapped_column(String(20), nullable=True)
    commit_sha: Mapped[str | None] = mapped_column(String(64), nullable=True)
    branch: Mapped[str | None] = mapped_column(String(255), nullable=True)
    pr_number: Mapped[int | None] = mapped_column(Integer, nullable=True)
    feedback_status: Mapped[str] = mapped_column(String(20), nullable=False, server_default="not_applicable")
    cancelled_reason: Mapped[str | None] = mapped_column(String(64), nullable=True)
    failed_scanners: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    trigger_metadata: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    __table_args__ = (
        sa.Index("ix_scanrun_tool_status", "tool", "status"),
        sa.Index("ix_scanrun_started_at", "started_at"),
        sa.Index("ix_scanrun_archived", "archived"),
        sa.Index("ix_scan_runs_pr_number", "pr_number"),
        sa.Index("ix_scan_runs_feedback_status", "feedback_status"),
        sa.CheckConstraint(
            "status IN ('queued', 'running', 'ingesting', 'completed', 'completed_with_merge_error', 'failed', 'cancelled')",
            name="ck_scan_runs_status",
        ),
        sa.CheckConstraint(
            "triggered_by IS NULL OR triggered_by IN ('scheduled','manual','webhook','ci','api')",
            name="ck_scan_runs_triggered_by",
        ),
        sa.CheckConstraint(
            "feedback_status IN ('not_applicable','pending','posted','failed','skipped')",
            name="ck_scan_runs_feedback_status",
        ),
    )


class ScanCheckpoint(Base):
    __tablename__ = "scan_checkpoints"

    tool: Mapped[str] = mapped_column(String(30), primary_key=True, default="secrets")
    asset_id: Mapped[str] = mapped_column(
        UUID(as_uuid=False),
        ForeignKey("assets.id", ondelete="CASCADE"),
        primary_key=True,
    )
    last_commit_sha: Mapped[str] = mapped_column(String(255), default="")
    last_commit_date: Mapped[str] = mapped_column(String(50), default="")


class Finding(Base):
    """Unified finding row — one per finding across all scanners.

    Secrets findings keep asset_id NULL (no repo-level scoping for org-wide
    secret scanning). The unique constraint on (tool, asset_id, identity_key)
    handles this correctly — Postgres allows duplicate NULL values in UNIQUE
    constraints, so secrets deduplicate by (tool, identity_key) effectively.
    """
    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    tool: Mapped[str] = mapped_column(String(30), nullable=False, index=True)
    asset_id: Mapped[str | None] = mapped_column(
        UUID(as_uuid=False),
        ForeignKey("assets.id", ondelete="RESTRICT"),
        nullable=True, index=True,
    )
    identity_key: Mapped[str] = mapped_column(String(512), nullable=False)
    state: Mapped[str] = mapped_column(String(20), nullable=False, default="open")
    review_status: Mapped[str | None] = mapped_column(String(20), nullable=True)
    severity: Mapped[str | None] = mapped_column(String(20), nullable=True)
    # True when this finding is a malicious-package report (OSV MAL-): the
    # package itself is malware, so it is kept open with no fix and surfaced
    # distinctly (remove, don't upgrade).
    malicious: Mapped[bool] = mapped_column(
        sa.Boolean, nullable=False, server_default=sa.text("false")
    )
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    fixed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    # engine values:
    #   "semgrep"   — code_scanning SAST engine that produced this finding
    #   "byo"       — finding came from a bring-your-own import
    #                 (assets/router.py byo_import endpoint)
    #   NULL        — non-code_scanning tools (deps, secrets, containers)
    engine: Mapped[str | None] = mapped_column(String(20), nullable=True)
    detail: Mapped[dict] = mapped_column(JSONB, default=dict)
    detail_blob_key: Mapped[str | None] = mapped_column(String(512), nullable=True)
    cve_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    file_path: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    title: Mapped[str | None] = mapped_column(String(512), nullable=True)
    rule_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    package_name: Mapped[str | None] = mapped_column(String(512), nullable=True)
    # The specific installed/affected version this finding is about (e.g. the
    # SBOM component version OSV matched). Lets vuln counts be attributed per
    # version, not just per package name. NULL when the source didn't resolve one.
    package_version: Mapped[str | None] = mapped_column(String(256), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)
    # Populated at ingest time from git blame; NULL when checkout is unavailable.
    introduced_by_commit_sha: Mapped[str | None] = mapped_column(String(64), nullable=True)
    introduced_by_author: Mapped[str | None] = mapped_column(String(255), nullable=True)
    introduced_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    introduced_by_pr_url: Mapped[str | None] = mapped_column(String(512), nullable=True)
    archived: Mapped[bool] = mapped_column(sa.Boolean, nullable=False, server_default=sa.text("false"))
    archived_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    archived_by_rule_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    risk_score: Mapped[int | None] = mapped_column(Integer, nullable=True)
    assignee_user_id: Mapped[str | None] = mapped_column(
        String(255),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    verdict: Mapped[str | None] = mapped_column(String(20), nullable=True)
    evidence: Mapped[list | None] = mapped_column(JSONB, nullable=True)
    exploit_chain: Mapped[str | None] = mapped_column(Text, nullable=True)
    verification_metadata: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    # Structured remediation payload promoted from `detail` at ingest. Lets
    # secrets/IaC/SAST findings carry a runner-emitted fix without it being
    # buried in the fat MinIO blob (recommended_fix is in no tool's LEAN_KEYS).
    recommended_fix: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    __table_args__ = (
        sa.UniqueConstraint("tool", "asset_id", "identity_key", name="uq_finding_tool_asset_key"),
        sa.Index("ix_finding_asset_state", "asset_id", "state"),
        sa.Index("ix_finding_asset_severity", "asset_id", "severity"),
        sa.Index("ix_findings_archived", "archived"),
        sa.Index("ix_finding_asset_assignee", "asset_id", "assignee_user_id"),
        sa.Index("ix_findings_verdict", "verdict"),
        sa.CheckConstraint(
            "risk_score IS NULL OR (risk_score >= 0 AND risk_score <= 100)",
            name="ck_findings_risk_score_range",
        ),
        sa.CheckConstraint(
            "state IN ('open', 'deferred', 'dismissed', 'fixed')",
            name="ck_findings_state",
        ),
        sa.CheckConstraint(
            "verdict IS NULL OR verdict IN ('confirmed','needs_verify','possible','ruled_out')",
            name="ck_findings_verdict",
        ),
        sa.CheckConstraint(
            "engine IS NULL OR engine IN ('semgrep', 'byo')",
            name="ck_findings_engine",
        ),
    )


class Sbom(Base):
    """SBOM metadata per asset — blobs stored in MinIO (sboms bucket)."""
    __tablename__ = "sboms"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    asset_id: Mapped[str] = mapped_column(
        UUID(as_uuid=False),
        ForeignKey("assets.id", ondelete="RESTRICT"),
        nullable=False, index=True,
    )
    commit_sha: Mapped[str | None] = mapped_column(String(255), nullable=True)
    # Repo web URL captured by the runner (self-hosted-aware); deep-links deps
    # findings, which are built backend-side and carry no per-finding location.
    html_url: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    s3_key: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    scanned_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    run_id: Mapped[str] = mapped_column(String(100), nullable=False)

    __table_args__ = (
        sa.UniqueConstraint("asset_id", name="uq_sbom_asset"),
    )


class SbomRun(Base):
    """One append-only row per ingested SBOM scan run for an asset.

    The single ``Sbom`` row only holds the latest run; these rows preserve
    prior runs so the snapshot-history picker is an indexed query keyed by
    ``(asset_id, scanned_at)`` rather than a MinIO bucket listing.
    """
    __tablename__ = "sbom_runs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    asset_id: Mapped[str] = mapped_column(
        UUID(as_uuid=False),
        ForeignKey("assets.id", ondelete="CASCADE"),
        nullable=False,
    )
    run_id: Mapped[str] = mapped_column(String(100), nullable=False)
    commit_sha: Mapped[str | None] = mapped_column(String(255), nullable=True)
    scanned_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    __table_args__ = (
        sa.Index("idx_sbom_runs_asset_scanned", "asset_id", "scanned_at"),
        sa.UniqueConstraint("asset_id", "run_id", name="uq_sbom_runs_asset_run"),
    )


class SbomComponent(Base):
    __tablename__ = "sbom_components"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    asset_id: Mapped[str] = mapped_column(
        UUID(as_uuid=False),
        ForeignKey("assets.id", ondelete="RESTRICT"),
        nullable=False,
    )
    sbom_id: Mapped[int | None] = mapped_column(Integer, ForeignKey("sboms.id", ondelete="CASCADE"), nullable=True)
    purl: Mapped[str] = mapped_column(String(512))
    name: Mapped[str] = mapped_column(String(255))
    version: Mapped[str] = mapped_column(String(512))
    ecosystem: Mapped[str] = mapped_column(String(100))
    source_tool: Mapped[str | None] = mapped_column(String(50), nullable=True)
    # Tri-state dependency origin: True=direct, False=transitive, NULL=unknown
    # (graph absent / container-OS / unresolved bom-ref). Classified at ingest.
    is_direct: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    # Normalized SPDX display string + the computed risk category (classified at
    # ingest by src/sbom/licenses.py). Nullable for legacy/license-less rows.
    license_expression: Mapped[str | None] = mapped_column(String(512), nullable=True)
    license_category: Mapped[str | None] = mapped_column(String(32), nullable=True)
    # Declared semver constraint for a direct dep (e.g. "^4.17.0"), used for
    # loose-range exposure evaluation; null for transitive deps / older SBOMs.
    declared_range: Mapped[str | None] = mapped_column(String(256), nullable=True)
    # Dependency scope for a direct dep: "dev" (dev/test/build-only) or "prod".
    # Drives dev-only-noise auto-triage. Null for transitive deps / older SBOMs.
    scope: Mapped[str | None] = mapped_column(String(16), nullable=True)
    # Where the dep is declared in the repo (manifest path + 1-indexed line) plus
    # a small surrounding code window, captured by the runner from the manifest.
    # Drives the finding drawer's code preview + repo deep-link. Null for
    # transitive deps / older SBOMs.
    manifest_path: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    manifest_line: Mapped[int | None] = mapped_column(Integer, nullable=True)
    manifest_snippet: Mapped[str | None] = mapped_column(Text, nullable=True)
    manifest_snippet_start: Mapped[int | None] = mapped_column(Integer, nullable=True)
    # For a container component: the image layer that introduced the package —
    # its digest and 0-based ordinal (bottom-most layer = 0). Null for repo
    # components and OS packages the SBOM can't attribute to a layer.
    layer_digest: Mapped[str | None] = mapped_column(String(80), nullable=True)
    layer_index: Mapped[int | None] = mapped_column(Integer, nullable=True)
    scanned_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    __table_args__ = (
        sa.Index("idx_sbom_components_asset_name", "asset_id", "name", "ecosystem"),
        sa.Index("idx_sbom_components_asset_purl", "asset_id", "purl"),
        sa.Index("idx_sbom_components_asset_license_cat", "asset_id", "license_category"),
        sa.UniqueConstraint("asset_id", "purl", name="uq_sbom_components_asset_purl"),
    )


class Decision(Base):
    """Human action on a finding — dismiss only. Reopen = delete row.

    asset_id is NULL for secrets findings (which keep asset_id=NULL on findings).
    The unique constraint allows NULL asset_id; secrets decisions deduplicate
    on (tool, identity_key) effectively since Postgres UNIQUE permits duplicate NULLs.
    """
    __tablename__ = "decisions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    tool: Mapped[str] = mapped_column(String(30), nullable=False)
    asset_id: Mapped[str | None] = mapped_column(
        UUID(as_uuid=False),
        ForeignKey("assets.id", ondelete="RESTRICT"),
        nullable=True,
    )
    identity_key: Mapped[str] = mapped_column(String(512), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False)
    reason: Mapped[str | None] = mapped_column(String(100), nullable=True)
    comment: Mapped[str | None] = mapped_column(Text, nullable=True)
    decided_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    decided_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    __table_args__ = (
        sa.UniqueConstraint("tool", "asset_id", "identity_key", name="uq_decision_tool_asset_key"),
        sa.Index("ix_decisions_asset_identity", "asset_id", "tool", "identity_key"),
    )


class FindingEvent(Base):
    """Append-only audit trail for finding state changes."""
    __tablename__ = "finding_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    finding_id: Mapped[int] = mapped_column(Integer, ForeignKey("findings.id"), nullable=False)
    from_state: Mapped[str | None] = mapped_column(String(20), nullable=True)
    to_state: Mapped[str] = mapped_column(String(20), nullable=False)
    triggered_by: Mapped[str] = mapped_column(String(20), nullable=False)
    actor: Mapped[str | None] = mapped_column(String(255), nullable=True)
    metadata_json: Mapped[dict | None] = mapped_column("metadata", JSONB, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    __table_args__ = (
        sa.Index("ix_finding_event_finding_id", "finding_id"),
    )




class NotificationDestination(Base):
    """Outbound delivery channel.

    destination_type is 'slack' | 'webhook' | 'email'.
    config is type-specific: webhook_url for Slack, url+secret for generic
    webhooks, to_addresses list for email.
    event_filter narrows which event types (and min severity) reach this dest.
    """
    __tablename__ = "notification_destinations"

    id: Mapped[int] = mapped_column(sa.BigInteger, primary_key=True, autoincrement=True)
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
        sa.UniqueConstraint('name', name='uq_notif_dest_name'),
        sa.CheckConstraint(
            "destination_type IN ('slack', 'webhook', 'email')",
            name='ck_notification_destinations_destination_type',
        ),
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
    # Retry bookkeeping: number of send attempts so far, when the next re-send is
    # due, and the full formatted payload retained only while a delivery is in
    # 'retry' so the worker can re-send without the original event.
    attempts: Mapped[int] = mapped_column(
        Integer, nullable=False, server_default="1", default=1
    )
    next_attempt_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    payload: Mapped[str | None] = mapped_column(Text, nullable=True)

    destination: Mapped["NotificationDestination"] = relationship(back_populates="deliveries")

    __table_args__ = (
        sa.UniqueConstraint('destination_id', 'event_id', name='uq_notif_delivery_dest_event'),
        sa.Index('ix_notif_deliveries_status', 'status', 'attempted_at'),
        sa.Index('ix_notif_deliveries_retry', 'status', 'next_attempt_at'),
        sa.CheckConstraint(
            "status IN ('delivered', 'failed', 'retry')",
            name="ck_notif_deliveries_status",
        ),
    )




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

    __table_args__ = (
        sa.Index('ix_notif_rules_priority', 'priority'),
    )





class ApiKey(Base):
    """Revocable API token — token stored only as SHA-256 hash."""
    __tablename__ = "api_keys"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
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
    allowed_source_ids: Mapped[dict | list | None] = mapped_column(JSONB, nullable=True)
    org_id: Mapped[str] = mapped_column(String(255), nullable=False, server_default="default")

    __table_args__ = (
        sa.Index("ix_api_keys_revoked_at", "revoked_at"),
        sa.Index("ix_api_keys_prefix", "prefix"),
    )



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
        sa.CheckConstraint(
            "status IN ('active', 'rotating', 'revoked')",
            name="ck_webhook_signing_secrets_status",
        ),
    )




class WebhookProcessedDelivery(Base):
    """Replay-dedup ledger of processed inbound webhook deliveries.

    Each authentic delivery carries a provider-unique id header (e.g.
    ``X-GitHub-Delivery``). Recording ``(provider, delivery_id)`` under a
    unique constraint lets a receiver reject a re-sent, still-signed payload
    before it is republished. Rows are pruned once they age out of any
    realistic provider retry window.
    """
    __tablename__ = "webhook_processed_deliveries"
    __table_args__ = (
        sa.UniqueConstraint("provider", "delivery_id", name="uq_webhook_delivery_provider_id"),
        sa.Index("ix_webhook_deliveries_received_at", "received_at"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    provider: Mapped[str] = mapped_column(String(32), nullable=False)
    delivery_id: Mapped[str] = mapped_column(String(255), nullable=False)
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)


class SlaPolicy(Base):
    """Per-severity remediation deadline policy."""
    __tablename__ = "sla_policies"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    severity: Mapped[str] = mapped_column(String(10), nullable=False)
    deadline_days: Mapped[int] = mapped_column(Integer, nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    __table_args__ = (
        sa.UniqueConstraint("severity", name="uq_sla_policy_severity"),
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




class Rule(Base):
    """Unified rule engine: SLA, scanner coverage, auto-dismiss, data retention.

    Conditions JSONB holds an all/any predicate tree — see rules_engine.conditions
    for evaluation semantics. Action JSONB is category-discriminated.
    """
    __tablename__ = "rules"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    category: Mapped[str] = mapped_column(String(32), nullable=False)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    priority: Mapped[int] = mapped_column(Integer, nullable=False, default=100)
    conditions: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    action: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    created_by: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)
    last_evaluated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    last_dry_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_dry_run_match_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    dry_run_confirmation_token: Mapped[str | None] = mapped_column(String(64), nullable=True)
    dry_run_confirmed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        sa.Index("ix_rules_category", "category"),
        sa.Index("ix_rules_enabled", "enabled"),
    )


class RuleViolation(Base):
    """Open / resolved violation event for a rule against a subject."""
    __tablename__ = "rule_violations"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    rule_id: Mapped[str] = mapped_column(String(64), ForeignKey("rules.id", ondelete="CASCADE"), nullable=False)
    subject_type: Mapped[str] = mapped_column(String(32), nullable=False)
    subject_id: Mapped[str] = mapped_column(String(128), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="open")
    opened_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    context: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    asset_id: Mapped[str] = mapped_column(
        UUID(as_uuid=False),
        ForeignKey("assets.id", ondelete="RESTRICT"),
        nullable=False, index=True,
    )

    __table_args__ = (
        sa.Index("ix_rule_violations_rule_status", "rule_id", "status"),
        sa.Index("ix_rule_violations_subject", "subject_type", "subject_id"),
        sa.Index(
            "uq_rule_violations_open_per_subject",
            "rule_id", "subject_type", "subject_id",
            unique=True,
            postgresql_where=sa.text("status = 'open'"),
        ),
    )


class RuleKillSwitch(Base):
    """Per-category kill switch that halts auto-dismiss when set.

    Row presence means the switch is active — delete the row to re-enable.
    """
    __tablename__ = "rule_kill_switches"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    category: Mapped[str] = mapped_column(String(32), nullable=False)
    killed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    killed_by: Mapped[str] = mapped_column(String(255), nullable=False)
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)

    __table_args__ = (
        sa.UniqueConstraint("category", name="uq_kill_switch_category"),
    )




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


class PackageReleaseDate(Base):
    """Cache of a package version's upstream publish date, from deps.dev.

    Populated lazily during ingest when the opt-in release-age enrichment is on,
    so a very recently published dependency version (a supply-chain freshness
    signal) can be flagged. Keyed by the deps.dev system + package name +
    version. ``published_at`` is null when deps.dev has no date for the version;
    the null is still cached to avoid re-querying a known miss.
    """
    __tablename__ = "package_release_dates"

    system: Mapped[str] = mapped_column(String(16), primary_key=True)
    name: Mapped[str] = mapped_column(String(512), primary_key=True)
    version: Mapped[str] = mapped_column(String(256), primary_key=True)
    published_at: Mapped[date | None] = mapped_column(Date(), nullable=True)
    fetched_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class BaseImageRecommendation(Base):
    """A scanned image's best newer base tag, proven by scanning candidates.

    Written by the opt-in base-image recommendation flow: after a container scan,
    each strictly-newer candidate tag is SBOM-scanned and its vulnerabilities are
    counted in memory (never persisted as findings), and the candidate with the
    fewest is stored here keyed by the *current* image digest. ``recommended_tag``
    is null when no candidate improves on the current image, so the "no upgrade
    helps" answer is cached too.
    """
    __tablename__ = "base_image_recommendations"

    image_digest: Mapped[str] = mapped_column(String(80), primary_key=True)
    current_ref: Mapped[str] = mapped_column(sa.Text, nullable=False)
    current_vuln_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    recommended_tag: Mapped[str | None] = mapped_column(sa.Text, nullable=True)
    recommended_vuln_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    candidates_scanned: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    computed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)




class UserSession(Base):
    """Server-side session store enabling revocation, rotation, and per-session
    enumeration in the admin UI — capabilities that stateless signed cookies
    can't provide. Lookups verify `revoked_at IS NULL AND expires_at > now()`.
    """

    __tablename__ = "user_sessions"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[str] = mapped_column(
        String(255),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    user_agent: Mapped[str | None] = mapped_column(Text, nullable=True)
    ip_address: Mapped[str | None] = mapped_column(INET, nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    revocation_reason: Mapped[str | None] = mapped_column(String(64), nullable=True)

    # Eager-load the user in the same SELECT so the gate never issues N+1 queries
    # when reading session.user.status or attaching session.user to request.state.
    user: Mapped["User"] = relationship("User", lazy="joined")

    __table_args__ = (
        sa.Index(
            "sessions_user_id_idx",
            "user_id",
            postgresql_where=sa.text("revoked_at IS NULL"),
        ),
        sa.Index(
            "sessions_expires_at_idx",
            "expires_at",
            postgresql_where=sa.text("revoked_at IS NULL"),
        ),
    )


class RateLimitBucket(Base):
    """Sliding-window rate-limit counter, keyed by endpoint+actor.

    Key format: "<endpoint>:<actor_kind>:<actor_id>"
      e.g. "/api/v1/auth/login:ip:198.51.100.42" or "/api/v1/auth/login:user:<user-uuid>"

    Server-side state so rate limits survive process restarts and span workers.
    """

    __tablename__ = "rate_limit_buckets"

    key: Mapped[str] = mapped_column(String(512), primary_key=True)
    window_start: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    request_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )


class Report(Base):
    """On-demand generated security report stored in MinIO."""
    __tablename__ = "reports"

    id: Mapped[int] = mapped_column(sa.BigInteger, primary_key=True, autoincrement=True)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    report_type: Mapped[str] = mapped_column(String(50), nullable=False)
    format: Mapped[str] = mapped_column(String(10), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="pending")
    filters: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    row_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    file_size_bytes: Mapped[int | None] = mapped_column(Integer, nullable=True)
    storage_key: Mapped[str | None] = mapped_column(String(500), nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_by: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    __table_args__ = (
        sa.Index("ix_reports_created_by_created_at", "created_by", "created_at"),
        sa.Index("ix_reports_expires_at", "expires_at"),
        sa.CheckConstraint(
            "status IN ('pending', 'completed', 'failed')",
            name="ck_reports_status",
        ),
    )


class ScheduledReport(Base):
    """Configuration row describing a recurring report generation + delivery.

    Generated on a cron/simple schedule by the scheduler tick. Each run
    materialises a Report row (via the existing generate_report path) and
    fans out delivery via NotificationDestinations referenced by destination_ids.
    """
    __tablename__ = "scheduled_reports"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    report_type: Mapped[str] = mapped_column(String(32), nullable=False)
    format: Mapped[str] = mapped_column(String(16), nullable=False)
    schedule_type: Mapped[str] = mapped_column(String(16), nullable=False)
    schedule_value: Mapped[str] = mapped_column(String(64), nullable=False)
    filters: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    destination_ids: Mapped[list[int]] = mapped_column(
        ARRAY(BigInteger), nullable=False, default=list,
    )
    created_by: Mapped[str] = mapped_column(String(255), nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_run_status: Mapped[str | None] = mapped_column(String(16), nullable=True)
    last_run_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow,
    )

    __table_args__ = (
        sa.CheckConstraint(
            "report_type IN ('findings', 'posture')",
            name="ck_scheduled_reports_type",
        ),
        sa.CheckConstraint(
            "format IN ('pdf', 'csv', 'json')",
            name="ck_scheduled_reports_format",
        ),
        sa.CheckConstraint(
            "schedule_type IN ('simple', 'cron')",
            name="ck_scheduled_reports_schedule_type",
        ),
        sa.CheckConstraint(
            "last_run_status IS NULL OR last_run_status IN ('success', 'failed')",
            name="ck_scheduled_reports_last_run_status",
        ),
        sa.Index("ix_scheduled_reports_enabled", "enabled"),
    )




class SavedView(Base):
    """Per-user saved filter/sort/group/page state for a surface (e.g. findings).

    `url_state` is the verbatim query-string param map serialized to JSONB.
    Default uniqueness is enforced at the service layer.
    """
    __tablename__ = "saved_views"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    user_id: Mapped[str] = mapped_column(String(255), nullable=False)
    surface: Mapped[str] = mapped_column(String(64), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    url_state: Mapped[dict] = mapped_column(JSONB, nullable=False)
    is_default: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    __table_args__ = (
        sa.UniqueConstraint("user_id", "surface", "name", name="uq_saved_views_user_surface_name"),
        sa.Index("ix_saved_views_user_surface", "user_id", "surface"),
    )


class Asset(Base):
    """Stable per-resource identity for repos and container images.

    Three ingestion paths converge through `external_ref` — see src/assets/refs.py
    for the canonical-string contract.
    """
    __tablename__ = "assets"

    id: Mapped[str] = mapped_column(
        UUID(as_uuid=False), primary_key=True,
        server_default=sa.text("gen_random_uuid()"),
    )
    type: Mapped[str] = mapped_column(String(32), nullable=False)
    source: Mapped[str] = mapped_column(String(32), nullable=False)
    source_ref: Mapped[str | None] = mapped_column(String(255), nullable=True)
    external_ref: Mapped[str] = mapped_column(String(512), nullable=False)
    display_name: Mapped[str] = mapped_column(String(512), nullable=False)
    asset_metadata: Mapped[dict] = mapped_column("metadata", JSONB, default=dict, nullable=False)
    # Scan-state — drives delta detection and coverage/staleness rules.
    manifest_set_hash: Mapped[str | None] = mapped_column(String(128), nullable=True)
    last_scanned_sha: Mapped[str | None] = mapped_column(String(64), nullable=True)
    tier: Mapped[str | None] = mapped_column(String(32), nullable=True)
    archived: Mapped[bool] = mapped_column(sa.Boolean, nullable=False, server_default=sa.text("false"))
    labels: Mapped[list[str] | None] = mapped_column(JSONB, nullable=True)
    image_registry: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False)

    __table_args__ = (
        sa.UniqueConstraint("external_ref", name="uq_assets_external_ref"),
        sa.CheckConstraint("type IN ('repo','image')", name="ck_assets_type"),
        sa.CheckConstraint(
            "source IN ('source_connection','manual_upload','byo_import')",
            name="ck_assets_source",
        ),
        sa.Index("ix_assets_source_ref", "source_ref"),
        sa.Index("ix_assets_type", "type"),
    )



class PostureSnapshot(Base):
    """Daily severity snapshot per asset.

    Written by the midnight UTC scheduler tick. The trend endpoint aggregates
    rows by snapshot_date for the caller's accessible asset_ids.
    """
    __tablename__ = "posture_snapshots"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    asset_id: Mapped[str] = mapped_column(
        UUID(as_uuid=False),
        ForeignKey("assets.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )
    snapshot_date: Mapped[date] = mapped_column(Date, nullable=False, index=True)
    severity_critical: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    severity_high: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    severity_medium: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    severity_low: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    risk_score: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    # Exploitability-weighted raw volume (pre-gauge) for this asset/day. The
    # trend sums this across assets then gauges once, so the line reflects KEV/
    # reachability weighting, not just severity counts.
    risk_weight: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0", default=0)
    new_findings: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    __table_args__ = (
        sa.UniqueConstraint("asset_id", "snapshot_date", name="uq_posture_snapshot_asset_date"),
    )


class LlmConfig(Base):
    """Per-org BYO LLM credentials + budgets."""
    __tablename__ = "llm_config"

    org_id: Mapped[str] = mapped_column(String(255), primary_key=True)
    api_key_enc: Mapped[str] = mapped_column(String(512), nullable=False)
    api_base_url: Mapped[str] = mapped_column(String(512), nullable=False)
    model: Mapped[str] = mapped_column(String(128), nullable=False)
    scan_token_budget: Mapped[int] = mapped_column(Integer, nullable=False, default=100_000)
    daily_token_budget: Mapped[int] = mapped_column(Integer, nullable=False, default=1_000_000)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow)


class ArgusConnection(Base):
    """Per-org connection to the hosted Argus threat-intel enrichment service."""
    __tablename__ = "argus_connection"

    org_id: Mapped[str] = mapped_column(String(255), primary_key=True)
    endpoint: Mapped[str] = mapped_column(String(512), nullable=False)
    token_endpoint: Mapped[str] = mapped_column(String(512), nullable=False)
    client_id: Mapped[str] = mapped_column(String(255), nullable=False)
    refresh_token_enc: Mapped[str] = mapped_column(String(2048), nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow)


class LlmUsageDaily(Base):
    """Per-org daily token-spend ledger."""
    __tablename__ = "llm_usage_daily"

    org_id: Mapped[str] = mapped_column(String(255), primary_key=True)
    date: Mapped[date] = mapped_column(Date, primary_key=True)
    tokens_in: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    tokens_out: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    scans: Mapped[int] = mapped_column(Integer, nullable=False, default=0)


class OsvAdvisory(Base):
    """Mirror of an OSV vulnerability advisory header.

    Body fields (description, references, full affected ranges with events)
    live in MinIO at the `blob_key` path — fetched lazily on the detail view.
    """

    __tablename__ = "osv_advisories"

    advisory_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    # ecosystem / blob_key are OSV-controlled free-form strings with no upstream
    # length bound (SUSE module ecosystems already run ~60 chars); use unbounded
    # TEXT so distro data can never truncate the mirror refresh.
    ecosystem: Mapped[str] = mapped_column(sa.Text, nullable=False)
    summary: Mapped[str | None] = mapped_column(sa.Text, nullable=True)
    severity: Mapped[str | None] = mapped_column(String(16), nullable=True)
    # "vulnerability" (default) or "malicious" — malicious-package reports
    # (OSV MAL- ids) are surfaced as remove-not-upgrade findings downstream.
    kind: Mapped[str] = mapped_column(
        String(20), nullable=False, server_default="vulnerability"
    )
    blob_key: Mapped[str] = mapped_column(sa.Text, nullable=False)
    published_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True), nullable=True)
    modified_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), nullable=False)
    refreshed_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), nullable=False)

    __table_args__ = (
        sa.Index("ix_osv_advisories_modified_at", "modified_at"),
        sa.Index("ix_osv_advisories_ecosystem", "ecosystem"),
    )


class OsvVulnerableRange(Base):
    """A single (package, version-range) row for an OSV advisory.

    One advisory can have N affected packages × N version ranges.
    Joined to `assets`/sbom contents at dispatch time to find affected orgs.
    """

    __tablename__ = "osv_vulnerable_ranges"

    id: Mapped[int] = mapped_column(sa.BigInteger, primary_key=True, autoincrement=True)
    advisory_id: Mapped[str] = mapped_column(
        String(64),
        sa.ForeignKey("osv_advisories.advisory_id", ondelete="CASCADE"),
        nullable=False,
    )
    # All OSV-controlled free-form strings — unbounded upstream, so TEXT (see OsvAdvisory).
    package_name: Mapped[str] = mapped_column(sa.Text, nullable=False)
    ecosystem: Mapped[str] = mapped_column(sa.Text, nullable=False)
    range_introduced: Mapped[str | None] = mapped_column(sa.Text, nullable=True)
    range_fixed: Mapped[str | None] = mapped_column(sa.Text, nullable=True)
    range_last_affected: Mapped[str | None] = mapped_column(sa.Text, nullable=True)

    __table_args__ = (
        sa.Index("ix_osv_ranges_pkg_eco", "ecosystem", "package_name"),
    )


class OsvRefreshRun(Base):
    """Audit log row for each OSV refresh + dispatch pass."""

    __tablename__ = "osv_refresh_runs"

    id: Mapped[int] = mapped_column(sa.BigInteger, primary_key=True, autoincrement=True)
    started_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), nullable=False)
    finished_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True), nullable=True)
    advisories_added: Mapped[int] = mapped_column(sa.Integer, nullable=False, server_default=sa.text("0"))
    advisories_changed: Mapped[int] = mapped_column(sa.Integer, nullable=False, server_default=sa.text("0"))
    jobs_enqueued: Mapped[int] = mapped_column(sa.Integer, nullable=False, server_default=sa.text("0"))
    error: Mapped[str | None] = mapped_column(sa.Text, nullable=True)
