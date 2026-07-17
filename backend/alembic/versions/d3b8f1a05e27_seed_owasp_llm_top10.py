"""seed OWASP LLM Top 10 compliance framework

Revision ID: d3b8f1a05e27
Revises: 0298e3de0fcd
Create Date: 2026-07-17 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'd3b8f1a05e27'
down_revision: Union[str, Sequence[str], None] = '0298e3de0fcd'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


_FRAMEWORK_ID = "owasp-llm-top10"

# (control_id, title, description, category) — OWASP Top 10 for LLM Applications (2025).
_CONTROLS = [
    ("LLM01", "Prompt Injection", "User- or content-borne input that alters the model's behavior against intent.", "Input"),
    ("LLM02", "Sensitive Information Disclosure", "The model or its tools leak secrets, PII, or proprietary data.", "Output"),
    ("LLM03", "Supply Chain", "Compromised models, dependencies, datasets, or tool/plugin sources.", "Supply Chain"),
    ("LLM04", "Data and Model Poisoning", "Training or context data manipulated to bias or backdoor behavior.", "Data"),
    ("LLM05", "Improper Output Handling", "Model output consumed by downstream systems without validation.", "Output"),
    ("LLM06", "Excessive Agency", "The system grants the model excessive permissions, tools, or autonomy.", "Agency"),
    ("LLM07", "System Prompt Leakage", "System or developer prompts exposed to users or attackers.", "Output"),
    ("LLM08", "Vector and Embedding Weaknesses", "Weaknesses in retrieval/embedding pipelines that enable injection or leakage.", "Retrieval"),
    ("LLM09", "Misinformation", "The model produces false or fabricated information relied upon downstream.", "Output"),
    ("LLM10", "Unbounded Consumption", "Uncontrolled resource use enabling denial-of-service or runaway cost.", "Availability"),
]


def upgrade() -> None:
    op.execute(
        sa.text(
            """
            INSERT INTO frameworks (id, label, description, is_custom, created_at, updated_at)
            VALUES (:id, :label, :descr, false, now(), now())
            ON CONFLICT (id) DO NOTHING
            """
        ).bindparams(
            id=_FRAMEWORK_ID,
            label="OWASP Top 10 for LLM Applications (2025)",
            descr="Security risks specific to applications built on large language models and AI agents.",
        )
    )
    stmt = sa.text(
        """
        INSERT INTO framework_controls (framework, control_id, title, description, category, is_custom, created_at)
        VALUES (:fw, :cid, :title, :descr, :cat, false, now())
        ON CONFLICT (framework, control_id) DO NOTHING
        """
    )
    for control_id, title, description, category in _CONTROLS:
        op.execute(
            stmt.bindparams(fw=_FRAMEWORK_ID, cid=control_id, title=title, descr=description, cat=category)
        )


def downgrade() -> None:
    raise NotImplementedError("Forward-only; no downgrade.")
