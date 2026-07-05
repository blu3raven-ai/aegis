"""add malicious-package columns

Revision ID: edc0ec32100b
Revises: 0d26dba68d33
Create Date: 2026-07-04 18:20:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "edc0ec32100b"
down_revision: Union[str, Sequence[str], None] = "0d26dba68d33"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Add classification columns for malicious-package (OSV MAL-) reports.

    ``osv_advisories.kind`` distinguishes malicious-package reports from
    ordinary vulnerabilities at the mirror layer; ``findings.malicious``
    promotes that class onto findings so they are kept open (no fix) and
    surfaced distinctly. Both default so existing rows migrate without a
    rewrite; the next OSV refresh backfills ``kind`` for MAL- advisories.
    """
    op.add_column(
        "osv_advisories",
        sa.Column(
            "kind",
            sa.String(length=20),
            nullable=False,
            server_default="vulnerability",
        ),
    )
    op.add_column(
        "findings",
        sa.Column(
            "malicious",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
    )


def downgrade() -> None:
    raise NotImplementedError("Forward-only; no downgrade.")
