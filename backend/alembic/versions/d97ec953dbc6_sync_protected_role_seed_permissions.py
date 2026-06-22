"""sync protected role seed permissions

Realign the three default protected roles (role_owner, role_admin,
role_viewer) with the permission catalog. Owner gains the new
``manage_owner_role`` permission so subsequent owner-only checks can
reference the catalog instead of inline ``role == "owner"``.

Safety guarantee: the UPDATE statements target the three known seed IDs
AND ``protected = true``. Customer-customised roles (``protected =
false``) are never touched.

Revision ID: d97ec953dbc6
Revises: b2d01d619813
Create Date: 2026-06-16 16:10:00.000000

"""
import json
from typing import Sequence, Union

from alembic import op
from sqlalchemy import text


# revision identifiers, used by Alembic.
revision: str = "d97ec953dbc6"
down_revision: Union[str, Sequence[str], None] = "b2d01d619813"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


_OWNER_PERMISSIONS = sorted([
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
    "view_audit",
    "manage_organisations",
    "refresh_dashboard",
    "view_rules",
    "manage_sla_rules",
    "manage_scanner_coverage_rules",
    "manage_auto_dismiss_rules",
    "manage_data_retention_rules",
    "manage_owner_role",
])

_ADMIN_PERMISSIONS = sorted([
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
    "view_audit",
    "manage_organisations",
    "refresh_dashboard",
    "view_rules",
    "manage_sla_rules",
    "manage_scanner_coverage_rules",
    "manage_auto_dismiss_rules",
    "manage_data_retention_rules",
])

_VIEWER_PERMISSIONS = sorted([
    "view_dashboards",
    "view_findings",
    "view_rules",
])


def _sync(role_id: str, permissions: list[str]) -> None:
    op.execute(
        text(
            """
            UPDATE roles
            SET permissions = CAST(:perms AS JSONB)
            WHERE id = :role_id AND protected = true
            """
        ).bindparams(role_id=role_id, perms=json.dumps(permissions))
    )


def upgrade() -> None:
    """Realign the three protected default roles with the catalog."""
    _sync("role_owner", _OWNER_PERMISSIONS)
    _sync("role_admin", _ADMIN_PERMISSIONS)
    _sync("role_viewer", _VIEWER_PERMISSIONS)


def downgrade() -> None:
    raise NotImplementedError("Forward-only; no downgrade.")
