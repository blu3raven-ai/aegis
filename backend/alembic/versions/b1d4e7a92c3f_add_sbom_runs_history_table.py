"""add sbom_runs run-history table

Revision ID: b1d4e7a92c3f
Revises: dc76ca71c5e7
Create Date: 2026-06-28 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'b1d4e7a92c3f'
down_revision: Union[str, Sequence[str], None] = 'dc76ca71c5e7'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Add the append-only sbom_runs table so the per-repo snapshot history is
    an indexed query instead of a MinIO bucket listing. Seed it with the latest
    run per asset from the single-row sboms table so existing repos keep a
    history entry without waiting for the next scan."""
    op.create_table(
        'sbom_runs',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('asset_id', sa.UUID(as_uuid=False), nullable=False),
        sa.Column('run_id', sa.String(length=100), nullable=False),
        sa.Column('commit_sha', sa.String(length=255), nullable=True),
        sa.Column('scanned_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['asset_id'], ['assets.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('asset_id', 'run_id', name='uq_sbom_runs_asset_run'),
    )
    op.create_index(
        'idx_sbom_runs_asset_scanned', 'sbom_runs', ['asset_id', 'scanned_at'], unique=False
    )

    op.execute(
        """
        INSERT INTO sbom_runs (asset_id, run_id, commit_sha, scanned_at)
        SELECT s.asset_id, s.run_id, s.commit_sha, s.scanned_at
        FROM sboms s
        JOIN assets a ON a.id = s.asset_id
        WHERE a.type = 'repo'
        ON CONFLICT (asset_id, run_id) DO NOTHING
        """
    )


def downgrade() -> None:
    raise NotImplementedError("Forward-only; no downgrade.")
