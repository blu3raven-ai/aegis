"""revoke all legacy sessions for unified-auth cutover

Revision ID: u5v6w7x8y9z0
Revises: t4u5v6w7x8y9
Create Date: 2026-06-03 10:47:09.803004

PR 3 of 4 in the FE/BE unification. After this migration, every active
session is revoked with reason 'unified_auth_cutover_v1'. Users must
log in again via the new cookie-auth path.

This is a one-way operation. Downgrade is a no-op — re-enabling old
sessions after a security cutover would negate the point of the cutover.
"""
from alembic import op
import sqlalchemy as sa


revision = "u5v6w7x8y9z0"
down_revision = "t4u5v6w7x8y9"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        sa.text(
            """
            UPDATE user_sessions
            SET revoked_at = now(),
                revocation_reason = 'unified_auth_cutover_v1'
            WHERE revoked_at IS NULL
            """
        )
    )


def downgrade() -> None:
    # One-way: re-enabling old sessions after a security cutover would
    # negate the point of the cutover. Operators wishing to "undo" PR 3
    # should revert the application code, not restore session rows.
    pass
