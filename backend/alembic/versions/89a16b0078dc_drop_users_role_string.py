"""drop legacy users.role string column; role_id is now the single source of truth

Revision ID: 89a16b0078dc
Revises: f66f1da9186c
Create Date: 2026-06-08
"""
from __future__ import annotations

from alembic import op

revision = "89a16b0078dc"
down_revision = "f66f1da9186c"


def upgrade() -> None:
    # Backfill role_id for any user where it's NULL but the legacy `role`
    # string is set. Maps the built-in kind strings onto their seeded role IDs.
    op.execute(
        """
        UPDATE users
        SET role_id = CASE role
            WHEN 'owner'    THEN 'role_owner'
            WHEN 'admin'    THEN 'role_admin'
            WHEN 'security' THEN 'role_security'
            WHEN 'viewer'   THEN 'role_viewer'
        END
        WHERE role_id IS NULL
          AND role IN ('owner', 'admin', 'security', 'viewer')
        """
    )

    op.drop_column("users", "role")


def downgrade() -> None:
    raise NotImplementedError("Forward-only schema; no downgrade.")
