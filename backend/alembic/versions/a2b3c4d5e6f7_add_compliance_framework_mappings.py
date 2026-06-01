"""add compliance_control_mappings and framework_controls tables

Revision ID: a2b3c4d5e6f7
Revises: f9a0b1c2d3e4
Create Date: 2026-05-31 00:00:00.000000

Phase 29: Compliance framework mapping. Findings and attack chains are
automatically mapped to SOC 2, ISO 27001, and PCI DSS controls using
rule-based logic keyed off scanner type, severity, and finding metadata.

Two tables:
  - framework_controls: reference data (static set of controls per framework)
  - compliance_control_mappings: per-finding / per-chain control mappings
    with confidence scores and human-readable rationale
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = 'a2b3c4d5e6f7'
down_revision: Union[str, Sequence[str], None] = 'f9a0b1c2d3e4'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

# ---------------------------------------------------------------------------
# Reference data: one row per control we care about
# ---------------------------------------------------------------------------

_CONTROLS: list[tuple[str, str, str, str, str]] = [
    # (framework, control_id, title, description, category)
    # SOC 2 Trust Service Criteria
    ("soc2", "CC6.1",
     "Logical and Physical Access Controls",
     "The entity implements logical access security software, infrastructure, "
     "and architectures over protected information assets to protect them from "
     "security events to meet the entity's objectives.",
     "Logical and Physical Access Controls"),
    ("soc2", "CC6.6",
     "System Hardening",
     "The entity implements controls to prevent or detect and act upon the "
     "introduction of unauthorized or malicious software.",
     "Logical and Physical Access Controls"),
    ("soc2", "CC6.7",
     "Restriction of Information Assets",
     "The entity restricts the transmission, movement, and removal of "
     "information to authorized internal and external users and processes.",
     "Logical and Physical Access Controls"),
    ("soc2", "CC6.8",
     "Prevention/Detection of Unauthorized Software",
     "The entity implements controls to prevent or detect and act upon the "
     "introduction of unauthorized or malicious software.",
     "Logical and Physical Access Controls"),
    ("soc2", "CC7.1",
     "System Monitoring",
     "To meet its objectives, the entity uses detection and monitoring "
     "procedures to identify changes to configurations or new vulnerabilities.",
     "System Operations"),
    ("soc2", "CC7.2",
     "Incident Response",
     "The entity monitors system components and the operation of those "
     "components for anomalies that are indicative of malicious acts, natural "
     "disasters, and errors affecting the entity's ability to meet its objectives.",
     "System Operations"),
    # ISO 27001:2022 Annex A
    ("iso27001", "A.5.23",
     "Information security for use of cloud services",
     "Processes for acquisition, use, management and exit from cloud services "
     "shall be established in accordance with the organisation's information "
     "security requirements.",
     "Technological Controls"),
    ("iso27001", "A.8.8",
     "Management of technical vulnerabilities",
     "Information about technical vulnerabilities of information systems in use "
     "shall be obtained in a timely fashion. The organisation's exposure to such "
     "vulnerabilities shall be evaluated and appropriate measures taken.",
     "Technological Controls"),
    ("iso27001", "A.8.9",
     "Configuration management",
     "Configurations, including security configurations, of hardware, software, "
     "services and networks shall be established, documented, implemented, "
     "monitored and reviewed.",
     "Technological Controls"),
    ("iso27001", "A.8.24",
     "Use of cryptography",
     "Rules for the effective use of cryptography, including cryptographic key "
     "management, shall be defined and implemented.",
     "Technological Controls"),
    ("iso27001", "A.9.4",
     "System and Application Access Control",
     "Access to systems and applications shall be controlled through a secure "
     "log-on procedure and shall restrict access to authorised users.",
     "Access Control"),
    # PCI DSS 4.0
    ("pci-dss", "6.2.4",
     "Secure software development",
     "Software engineering techniques or other methods are defined and in use "
     "by software development personnel to prevent or mitigate common software "
     "attacks and related vulnerabilities.",
     "Develop and Maintain Secure Systems and Software"),
    ("pci-dss", "6.3.1",
     "Identify vulnerabilities",
     "Security vulnerabilities are identified and managed using an industry-"
     "recognised vulnerability identification process.",
     "Develop and Maintain Secure Systems and Software"),
    ("pci-dss", "6.3.3",
     "All system components protected from known vulnerabilities",
     "All system components are protected from known vulnerabilities by "
     "installing applicable security patches/updates.",
     "Develop and Maintain Secure Systems and Software"),
    ("pci-dss", "8.3.6",
     "Cryptography to render PAN unreadable",
     "If used as a security control, the minimum cryptographic key strength "
     "and algorithm requirements are defined and implemented.",
     "Identify Users and Authenticate Access to System Components"),
    ("pci-dss", "11.3.1",
     "Vulnerabilities identified, ranked, addressed",
     "Internal vulnerability scans are performed via authenticated scanning "
     "at least once every three months.",
     "Test Security of Systems and Networks Regularly"),
]


def upgrade() -> None:
    # ── reference table ──────────────────────────────────────────────────────

    fc_table = op.create_table(
        'framework_controls',
        sa.Column('id', sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column('framework', sa.String(64), nullable=False),
        sa.Column('control_id', sa.String(64), nullable=False),
        sa.Column('title', sa.String(255), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('category', sa.String(128), nullable=True),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('framework', 'control_id', name='uq_framework_control'),
    )
    op.create_index('ix_framework_controls_fw', 'framework_controls', ['framework'])

    # Seed reference controls
    op.bulk_insert(fc_table, [
        {
            "framework": fw,
            "control_id": cid,
            "title": title,
            "description": desc,
            "category": cat,
        }
        for fw, cid, title, desc, cat in _CONTROLS
    ])

    # ── mappings table ────────────────────────────────────────────────────────

    op.create_table(
        'compliance_control_mappings',
        sa.Column('id', sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column('finding_id', sa.BigInteger(), nullable=True),
        sa.Column('chain_id', sa.String(26), nullable=True),
        sa.Column('framework', sa.String(64), nullable=False),
        sa.Column('control_id', sa.String(64), nullable=False),
        sa.Column('confidence', sa.Float(), nullable=False),
        sa.Column('rationale', sa.Text(), nullable=True),
        sa.Column('created_at', sa.TIMESTAMP(timezone=True), nullable=False, server_default=sa.text('now()')),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_compliance_finding', 'compliance_control_mappings', ['finding_id'])
    op.create_index('ix_compliance_chain', 'compliance_control_mappings', ['chain_id'])
    op.create_index('ix_compliance_framework_control', 'compliance_control_mappings', ['framework', 'control_id'])


def downgrade() -> None:
    op.drop_index('ix_compliance_framework_control', table_name='compliance_control_mappings')
    op.drop_index('ix_compliance_chain', table_name='compliance_control_mappings')
    op.drop_index('ix_compliance_finding', table_name='compliance_control_mappings')
    op.drop_table('compliance_control_mappings')

    op.drop_index('ix_framework_controls_fw', table_name='framework_controls')
    op.drop_table('framework_controls')
