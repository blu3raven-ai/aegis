"""grant reveal_secret to roles with review_findings

Revision ID: 97155195d338
Revises: 37051b2b381d
Create Date: 2026-07-03 14:39:42.176652

Data migration. Revealing a finding's raw secret value moved from the
``review_findings`` permission to a dedicated, more-sensitive ``reveal_secret``
permission. To preserve existing behaviour (reveal was gated on
``review_findings``), grant ``reveal_secret`` to every role that already holds
``review_findings``. There is deliberately no IMPLIED link between the two, so
an admin can now revoke ``reveal_secret`` from a triage-only role without
touching its ``review_findings`` grant.
"""
import json
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '97155195d338'
down_revision: Union[str, Sequence[str], None] = '37051b2b381d'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    conn = op.get_bind()
    rows = conn.execute(sa.text("SELECT id, permissions FROM roles")).mappings().all()
    for row in rows:
        perms = row["permissions"] or []
        if not isinstance(perms, list):
            continue
        if "review_findings" in perms and "reveal_secret" not in perms:
            new_perms = sorted(set(perms) | {"reveal_secret"})
            conn.execute(
                sa.text("UPDATE roles SET permissions = CAST(:p AS jsonb) WHERE id = :id"),
                {"p": json.dumps(new_perms), "id": row["id"]},
            )


def downgrade() -> None:
    raise NotImplementedError("Forward-only; no downgrade.")
