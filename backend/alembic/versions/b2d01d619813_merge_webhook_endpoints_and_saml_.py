"""merge webhook_endpoints and saml_validate heads

Revision ID: b2d01d619813
Revises: 7e11f6ddc4e2, 94bea03f1c16
Create Date: 2026-06-16 16:02:40.628321

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'b2d01d619813'
down_revision: Union[str, Sequence[str], None] = ('7e11f6ddc4e2', '94bea03f1c16')
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    pass


def downgrade() -> None:
    raise NotImplementedError("Forward-only; no downgrade.")
