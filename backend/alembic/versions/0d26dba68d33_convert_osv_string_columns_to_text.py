"""widen osv ecosystem column to 64

Revision ID: 0d26dba68d33
Revises: 97155195d338
Create Date: 2026-07-04 17:47:32.564622

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '0d26dba68d33'
down_revision: Union[str, Sequence[str], None] = '97155195d338'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Widen `ecosystem` to hold long OSV distro identifiers.

    Real OSV ecosystem strings for Linux-distro advisories exceed 32 chars
    (e.g. ``Ubuntu:Pro:FIPS-updates:18.04:LTS`` at 33, ``Red Hat:enterprise_linux:3::desktop``
    at 35), which truncated the nightly OSV refresh mid-insert. Widening is a
    non-destructive metadata change; no data rewrite occurs.
    """
    op.alter_column(
        "osv_advisories",
        "ecosystem",
        existing_type=sa.String(length=32),
        type_=sa.String(length=64),
        existing_nullable=False,
    )
    op.alter_column(
        "osv_vulnerable_ranges",
        "ecosystem",
        existing_type=sa.String(length=32),
        type_=sa.String(length=64),
        existing_nullable=False,
    )


def downgrade() -> None:
    raise NotImplementedError("Forward-only; no downgrade.")
