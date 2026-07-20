"""encrypt notification destination config secrets

Encrypts the previously-cleartext secret-bearing values in
``notification_destinations.config`` (``secret``, ``webhook_url``, and each
``_signing_secrets[].raw``) so they match every other secret class stored at
rest. Idempotent: values already encrypted are left as-is.

Revision ID: d7f3a1c9e42b
Revises: c4e19a7b2f83
Create Date: 2026-07-20 00:00:00.000000

"""
import json
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = 'd7f3a1c9e42b'
down_revision: Union[str, Sequence[str], None] = 'c4e19a7b2f83'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    from src.shared.encryption import encrypt_string, is_encrypted

    def _enc(value):
        if isinstance(value, str) and value and not is_encrypted(value):
            return encrypt_string(value)
        return value

    bind = op.get_bind()
    rows = bind.execute(
        sa.text("SELECT id, config FROM notification_destinations")
    ).fetchall()

    for row_id, config in rows:
        if not isinstance(config, dict):
            continue
        new_config = dict(config)
        changed = False

        for key in ("secret", "webhook_url"):
            enc = _enc(new_config.get(key))
            if enc is not new_config.get(key):
                new_config[key] = enc
                changed = True

        secrets_list = new_config.get("_signing_secrets")
        if isinstance(secrets_list, list):
            rebuilt = []
            for entry in secrets_list:
                if isinstance(entry, dict) and isinstance(entry.get("raw"), str):
                    enc = _enc(entry["raw"])
                    if enc is not entry["raw"]:
                        entry = {**entry, "raw": enc}
                        changed = True
                rebuilt.append(entry)
            new_config["_signing_secrets"] = rebuilt

        if changed:
            bind.execute(
                sa.text(
                    "UPDATE notification_destinations SET config = CAST(:cfg AS JSONB) "
                    "WHERE id = :id"
                ).bindparams(cfg=json.dumps(new_config), id=row_id)
            )


def downgrade() -> None:
    raise NotImplementedError("Forward-only; no downgrade.")
