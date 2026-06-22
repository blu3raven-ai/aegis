"""Seed default data on first run (empty database)."""
from __future__ import annotations

import hashlib
import logging
import os
import secrets
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.db.models import AppConfig, Role, User
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
        session.add(AppConfig(id=1, config={}, updated_at=datetime.now(timezone.utc)))

    await session.flush()
    logger.info("Admin user '%s' seeded from ADMIN_PASSWORD env var.", username)
