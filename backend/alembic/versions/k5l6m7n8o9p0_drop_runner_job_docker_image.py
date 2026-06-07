"""drop docker_image column from runner_jobs

Revision ID: k5l6m7n8o9p0
Revises: j4k5l6m7n8o9
Create Date: 2026-06-02 00:00:00.000000

The docker_image column was a vestige of the Docker-spawn scanner model.
Embedded scanners ignore it entirely, so the column is dead weight.
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "k5l6m7n8o9p0"
down_revision: Union[str, Sequence[str], None] = "j4k5l6m7n8o9"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.drop_column("runner_jobs", "docker_image")


def downgrade() -> None:
    op.add_column("runner_jobs", sa.Column("docker_image", sa.String(512), nullable=False, server_default=""))
