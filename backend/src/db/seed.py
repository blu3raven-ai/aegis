"""Seed default data on first run (empty database)."""
from __future__ import annotations

import hashlib
import logging
import os
import secrets
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.db.models import AppConfig, Role, Rule, User
from src.authz.roles.service import BUILTIN_PERMISSION_IDS

logger = logging.getLogger(__name__)

DEFAULT_ROLES = [
    {
        "id": "role_owner",
        "name": "Owner",
        "description": "Protected system role with full access.",
        "permissions": sorted(list(BUILTIN_PERMISSION_IDS)),
        "protected": True,
    },
    {
        "id": "role_admin",
        "name": "Admin",
        "description": "Workspace administration role.",
        "permissions": sorted([
            "view_dashboards",
            "view_findings",
            "review_findings",
            "reveal_secret",
            "export_findings",
            "run_scans",
            "cancel_scans",
            "view_scan_history",
            "view_reports",
            "export_reports",
            "view_settings",
            "manage_settings",
            "view_users",
            "manage_users",
            "view_roles",
            "manage_roles",
            "view_access_scope",
            "manage_access_scope",
            "view_sources",
            "manage_sources",
            "manage_runners",
            "view_audit",
            "manage_organisations",
            "refresh_dashboard",
            "view_rules",
            "manage_sla_rules",
            "manage_scanner_coverage_rules",
            "manage_auto_dismiss_rules",
            "manage_data_retention_rules",
        ]),
        "protected": True,
    },
    {
        "id": "role_security",
        "name": "Security",
        "description": "Security focused role with finding review capabilities.",
        "permissions": sorted([
            "view_dashboards",
            "view_findings",
            "review_findings",
            "reveal_secret",
            "run_scans",
            "view_settings",
            "refresh_dashboard",
            "view_rules",
            "manage_sla_rules",
        ]),
        "protected": True,
    },
    {
        "id": "role_viewer",
        "name": "Viewer",
        "description": "Read-only access to findings.",
        "permissions": sorted([
            "view_dashboards",
            "view_findings",
            "view_rules",
        ]),
        "protected": True,
    },
]


_DEFAULT_RULES = [
    # SLA tiers — one per severity level, ascending priority
    {
        "category": "sla",
        "name": "Critical — 7-day SLA",
        "description": "Critical findings must be remediated within 7 days.",
        "priority": 10,
        "conditions": {"field": "severity", "op": "eq", "value": "critical"},
        "action": {"deadline_days": 7, "escalations": []},
    },
    {
        "category": "sla",
        "name": "High — 30-day SLA",
        "description": "High findings must be remediated within 30 days.",
        "priority": 20,
        "conditions": {"field": "severity", "op": "eq", "value": "high"},
        "action": {"deadline_days": 30, "escalations": []},
    },
    {
        "category": "sla",
        "name": "Medium — 90-day SLA",
        "description": "Medium findings must be remediated within 90 days.",
        "priority": 30,
        "conditions": {"field": "severity", "op": "eq", "value": "medium"},
        "action": {"deadline_days": 90, "escalations": []},
    },
    {
        "category": "sla",
        "name": "Low — 180-day SLA",
        "description": "Low findings must be remediated within 180 days.",
        "priority": 40,
        "conditions": {"field": "severity", "op": "eq", "value": "low"},
        "action": {"deadline_days": 180, "escalations": []},
    },
    # Scanner coverage — catch-all baseline for all repos
    {
        "category": "scanner_coverage",
        "name": "Baseline scanning",
        "description": "All repositories must run every available scanner.",
        "priority": 100,
        "conditions": {},
        "action": {
            "type": "require_scanners",
            "required_scanners": [
                "dependencies_scanning",
                "code_scanning",
                "container_scanning",
                "secret_scanning",
            ],
        },
    },
]


async def seed_default_rules(session: AsyncSession) -> None:
    """Seed default SLA tiers and scanner coverage rule if no rules exist yet.

    Runs on every startup but is a no-op once any rule exists, so it is safe
    for both fresh installs and existing deployments.
    """
    result = await session.execute(select(Rule).limit(1))
    if result.scalars().first() is not None:
        return

    logger.info("No rules found — seeding default SLA tiers and baseline scanner coverage rule.")
    now = datetime.now(timezone.utc)

    for rule_data in _DEFAULT_RULES:
        category = rule_data["category"]
        rule_id = f"{category.replace('_', '-')}-{secrets.token_urlsafe(8)}"
        session.add(Rule(
            id=rule_id,
            category=category,
            name=rule_data["name"],
            description=rule_data["description"],
            enabled=True,
            priority=rule_data["priority"],
            conditions=rule_data["conditions"],
            action=rule_data["action"],
            created_by="system",
            created_at=now,
            updated_at=now,
        ))

    await session.flush()
    logger.info("Default rules seeded.")


async def seed_if_empty(session: AsyncSession) -> None:
    """Seed default roles, admin user, and config if the database is empty."""
    result = await session.execute(select(User).limit(1))
    if result.scalars().first() is not None:
        logger.info("Database already seeded — skipping.")
        return

    logger.info("Empty database detected — seeding defaults...")

    # Seed roles (skip if already exist)
    for role_data in DEFAULT_ROLES:
        existing_role = await session.get(Role, role_data["id"])
        if not existing_role:
            session.add(Role(
                id=role_data["id"],
                name=role_data["name"],
                description=role_data["description"],
                permissions=role_data["permissions"],
                protected=role_data["protected"],
                created_at=datetime.now(timezone.utc),
            ))

    # Seed admin user (scrypt format matching frontend's verifyPassword)
    password = os.environ.get("ADMIN_PASSWORD", "").strip()
    if not password:
        # Half-seeding (roles + AppConfig but no admin user) leaves the
        # workspace permanently locked out because the next boot sees a
        # non-empty DB and skips seeding. Refuse the entire transaction so
        # the operator sets ADMIN_PASSWORD and retries cleanly.
        raise RuntimeError(
            "ADMIN_PASSWORD environment variable is required for initial seed. "
            "Set it before first boot; subsequent boots can omit it once the admin user exists."
        )

    username = os.environ.get("ADMIN_USERNAME", "admin").strip()
    email = os.environ.get("ADMIN_EMAIL", "admin@example.com").strip()

    salt = os.urandom(16)
    key = hashlib.scrypt(password.encode(), salt=salt, n=16384, r=8, p=1, dklen=64)
    password_hash = f"scrypt:v1:{salt.hex()}:{key.hex()}"

    session.add(User(
        id=f"usr_{secrets.token_hex(8)}",
        username=username,
        email=email,
        password_hash=password_hash,
        role_id="role_owner",
        status="active",
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    ))

    # Upsert app_config to avoid duplicate key on re-seed
    existing_config = await session.get(AppConfig, 1)
    if not existing_config:
        session.add(AppConfig(id=1, config={"runners": {"mode": "remote"}}, updated_at=datetime.now(timezone.utc)))

    await session.flush()
    logger.info("Admin user '%s' seeded from ADMIN_PASSWORD env var.", username)
