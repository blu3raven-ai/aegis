"""grant rules permissions to existing seeded roles

Revision ID: y9z0a1b2c3d4
Revises: x8y9z0a1b2c3
Create Date: 2026-06-04

Adds the rules RBAC permission strings to existing seeded role rows so
that deployments past first-run seed get the new permissions wired up
without manual intervention. New installs receive these grants from
db/seed.py's DEFAULT_ROLES.
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op


revision = "y9z0a1b2c3d4"
down_revision = "x8y9z0a1b2c3"
branch_labels = None
depends_on = None


_ALL_RULE_PERMISSIONS = (
    "view_rules",
    "manage_sla_rules",
    "manage_scanner_coverage_rules",
    "manage_auto_dismiss_rules",
    "manage_data_retention_rules",
)

_ROLE_GRANTS: dict[str, tuple[str, ...]] = {
    "role_owner": _ALL_RULE_PERMISSIONS,
    "role_admin": _ALL_RULE_PERMISSIONS,
    "role_security": ("view_rules", "manage_sla_rules"),
    "role_viewer": ("view_rules",),
}


def upgrade() -> None:
    bind = op.get_bind()
    for role_id, perms in _ROLE_GRANTS.items():
        for perm in perms:
            bind.execute(
                sa.text(
                    """
                    UPDATE roles
                    SET permissions = permissions || to_jsonb(CAST(:perm AS text))
                    WHERE id = :role_id
                      AND NOT (permissions ? :perm)
                    """
                ).bindparams(perm=perm, role_id=role_id)
            )


def downgrade() -> None:
    bind = op.get_bind()
    for role_id, perms in _ROLE_GRANTS.items():
        for perm in perms:
            bind.execute(
                sa.text(
                    """
                    UPDATE roles
                    SET permissions = permissions - :perm
                    WHERE id = :role_id
                    """
                ).bindparams(perm=perm, role_id=role_id)
            )
