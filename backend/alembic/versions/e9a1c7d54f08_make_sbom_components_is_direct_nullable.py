"""make sbom_components.is_direct nullable

Revision ID: e9a1c7d54f08
Revises: c4e8a1f93b27
Create Date: 2026-06-28 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'e9a1c7d54f08'
down_revision: Union[str, Sequence[str], None] = 'c4e8a1f93b27'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Make is_direct a tri-state: True=direct, False=transitive, NULL=unknown.
    The column previously hardcoded True for every row; NULL now honestly
    represents components whose origin can't be determined (no dependency graph,
    container/OS packages). Existing rows self-correct on the asset's next scan."""
    op.alter_column(
        "sbom_components", "is_direct",
        existing_type=sa.Boolean(),
        nullable=True,
        server_default=None,
    )


def downgrade() -> None:
    raise NotImplementedError("Forward-only; no downgrade.")
