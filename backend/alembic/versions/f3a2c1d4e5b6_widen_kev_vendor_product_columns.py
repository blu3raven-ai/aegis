"""widen kev vendor_product columns

Revision ID: f3a2c1d4e5b6
Revises: e8a2c51f9d04
Create Date: 2026-07-21 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = 'f3a2c1d4e5b6'
down_revision: Union[str, Sequence[str], None] = 'e8a2c51f9d04'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # CISA KEV catalog entries occasionally carry vendor_project / product
    # strings longer than 120 chars, which aborted the bulk upsert with
    # "value too long for type character varying(120)". Widen both to 255.
    op.alter_column(
        'kev_entries', 'vendor_project',
        existing_type=sa.String(length=120),
        type_=sa.String(length=255),
        existing_nullable=True,
    )
    op.alter_column(
        'kev_entries', 'product',
        existing_type=sa.String(length=120),
        type_=sa.String(length=255),
        existing_nullable=True,
    )


def downgrade() -> None:
    raise NotImplementedError("Forward-only; no downgrade.")
