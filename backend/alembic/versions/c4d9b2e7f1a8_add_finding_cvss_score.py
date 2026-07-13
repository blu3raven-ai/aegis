"""add finding cvss_score column

Revision ID: c4d9b2e7f1a8
Revises: fa4839583a0a
Create Date: 2026-07-13

Promotes the CVSS 3.1 base score from ``verification_metadata`` into a typed,
sortable column, and backfills already-scored findings from the JSONB.
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "c4d9b2e7f1a8"
down_revision: Union[str, Sequence[str], None] = "fa4839583a0a"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("findings", sa.Column("cvss_score", sa.Float(), nullable=True))
    # Backfill existing findings from the JSONB score written by the verifier.
    op.execute(
        """
        UPDATE findings
        SET cvss_score = (verification_metadata ->> 'cvss_score')::double precision
        WHERE verification_metadata ? 'cvss_score'
          AND cvss_score IS NULL
        """
    )


def downgrade() -> None:
    raise NotImplementedError("Forward-only; no downgrade.")
