"""add base_image_recommendations

Revision ID: 911a59a2ddc5
Revises: 94927735cbeb
Create Date: 2026-07-05 08:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "911a59a2ddc5"
down_revision: Union[str, Sequence[str], None] = "94927735cbeb"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Per-image best newer base tag, keyed by the current image digest.

    Populated by the opt-in base-image recommendation flow. ``recommended_tag``
    null means no candidate improved on the current image (cached negative).
    """
    op.create_table(
        "base_image_recommendations",
        sa.Column("image_digest", sa.String(length=80), nullable=False),
        sa.Column("current_ref", sa.Text(), nullable=False),
        sa.Column("current_vuln_count", sa.Integer(), nullable=False),
        sa.Column("recommended_tag", sa.Text(), nullable=True),
        sa.Column("recommended_vuln_count", sa.Integer(), nullable=True),
        sa.Column("candidates_scanned", sa.Integer(), nullable=False),
        sa.Column("computed_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("image_digest"),
    )


def downgrade() -> None:
    raise NotImplementedError("Forward-only; no downgrade.")
