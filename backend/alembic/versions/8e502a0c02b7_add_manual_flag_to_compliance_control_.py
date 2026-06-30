"""add manual flag to compliance control mappings

Revision ID: 8e502a0c02b7
Revises: e446545d45cd
Create Date: 2026-06-27 23:05:33.214363

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '8e502a0c02b7'
down_revision: Union[str, Sequence[str], None] = 'e446545d45cd'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "compliance_control_mappings",
        sa.Column(
            "manual",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
    )
    op.create_unique_constraint(
        "uq_compliance_mapping_finding_control",
        "compliance_control_mappings",
        ["finding_id", "framework", "control_id"],
    )


def downgrade() -> None:
    raise NotImplementedError("Forward-only; no downgrade.")
