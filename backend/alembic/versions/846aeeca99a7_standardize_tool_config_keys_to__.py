"""standardize tool config keys to _scanning suffix

Renames the keys under app_config.config['tools'] so they match the
wire-level scanner-tool naming from migration 9432aed20734:

  dependencies      → dependencies_scanning
  containerScanning → container_scanning
  codeScanning      → code_scanning
  secrets           → secret_scanning
  iacSecurity       → iac_scanning   (note: drops the misleading 'Security' suffix)

Each rename is one UPDATE: when the old key is present, copy its value to
the new key and delete the old. Configs that don't carry the key (partial
or freshly-bootstrapped rows) are skipped via the IS NOT NULL guard.

Forward-only per CLAUDE.md.

Revision ID: 846aeeca99a7
Revises: 9432aed20734
Create Date: 2026-06-17 00:01:52.143553

"""
from typing import Sequence, Union

from alembic import op
from sqlalchemy import text


# revision identifiers, used by Alembic.
revision: str = '846aeeca99a7'
down_revision: Union[str, Sequence[str], None] = '9432aed20734'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


_MAPPING = {
    "dependencies": "dependencies_scanning",
    "containerScanning": "container_scanning",
    "codeScanning": "code_scanning",
    "secrets": "secret_scanning",
    "iacSecurity": "iac_scanning",
}


def upgrade() -> None:
    for old, new in _MAPPING.items():
        op.execute(
            text(
                """
                UPDATE app_config
                SET config = jsonb_set(
                    (config #- ARRAY['tools', :old])::jsonb,
                    ARRAY['tools', :new],
                    config #> ARRAY['tools', :old],
                    true
                )
                WHERE config #> ARRAY['tools', :old] IS NOT NULL
                """
            ).bindparams(old=old, new=new)
        )


def downgrade() -> None:
    raise NotImplementedError("Forward-only; no downgrade.")
