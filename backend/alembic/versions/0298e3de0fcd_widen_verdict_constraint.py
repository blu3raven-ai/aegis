"""widen verdict constraint

Revision ID: 0298e3de0fcd
Revises: 7874c5c659a3
Create Date: 2026-07-15 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op


# revision identifiers, used by Alembic.
revision: str = '0298e3de0fcd'
down_revision: Union[str, Sequence[str], None] = '7874c5c659a3'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.drop_constraint("ck_findings_verdict", "findings", type_="check")
    op.create_check_constraint(
        "ck_findings_verdict",
        "findings",
        "verdict IS NULL OR verdict IN "
        "('confirmed','needs_verify','needs_runtime_verification','possible','ruled_out')",
    )


def downgrade() -> None:
    raise NotImplementedError("Forward-only; no downgrade.")
