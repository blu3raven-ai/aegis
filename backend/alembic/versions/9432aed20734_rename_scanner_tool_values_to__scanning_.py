"""rename scanner tool values to _scanning suffix

Aligns scanner tool identifiers stored as string values in scan_runs.tool
and findings.tool with the codebase-wide convention that every scanner
name carries a `_scanning` suffix (already true for `code_scanning` and
`container_scanning`):

  dependencies → dependencies_scanning
  secrets      → secret_scanning   (note: singular)
  iac          → iac_scanning

The mapping must run on both `scan_runs.tool` and `findings.tool` so the
data and the new code agree. Coordinate the deploy: backend + runner
images must roll out together, since runner workers switch on
`job_type` strings sourced from these names.

Revision ID: 9432aed20734
Revises: d97ec953dbc6
Create Date: 2026-06-16 23:05:14.417985

"""
from typing import Sequence, Union

from alembic import op
from sqlalchemy import text


# revision identifiers, used by Alembic.
revision: str = '9432aed20734'
down_revision: Union[str, Sequence[str], None] = 'd97ec953dbc6'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


_MAPPING = {
    "dependencies": "dependencies_scanning",
    "secrets": "secret_scanning",
    "iac": "iac_scanning",
}


def upgrade() -> None:
    for old, new in _MAPPING.items():
        op.execute(
            text("UPDATE scan_runs SET tool = :new WHERE tool = :old").bindparams(old=old, new=new)
        )
        op.execute(
            text("UPDATE findings SET tool = :new WHERE tool = :old").bindparams(old=old, new=new)
        )


def downgrade() -> None:
    raise NotImplementedError("Forward-only; no downgrade.")
