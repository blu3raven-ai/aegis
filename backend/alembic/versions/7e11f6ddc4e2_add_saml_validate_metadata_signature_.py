"""add saml_validate_metadata_signature column

Revision ID: 7e11f6ddc4e2
Revises: 7dccacda3c43
Create Date: 2026-06-16 15:04:14.285260

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = '7e11f6ddc4e2'
down_revision: Union[str, Sequence[str], None] = '7dccacda3c43'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        'sso_config',
        sa.Column(
            'saml_validate_metadata_signature',
            sa.Boolean(),
            server_default=sa.text('false'),
            nullable=False,
        ),
    )


def downgrade() -> None:
    raise NotImplementedError("Forward-only; no downgrade.")
