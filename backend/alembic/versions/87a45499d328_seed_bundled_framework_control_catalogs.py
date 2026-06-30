"""seed bundled framework control catalogs

Revision ID: 87a45499d328
Revises: b3c1a9f5e2d4
Create Date: 2026-06-27 18:11:00.778066

The bundled frameworks (SOC 2, ISO 27001, PCI DSS) shipped with no control rows,
so the compliance UI rendered empty and the finding->control mappings pointed at
controls that didn't exist as rows. This seeds a faithful, representative control
catalog for each so the framework summaries populate and existing mappings light
up. Every control id the auto-mapper emits is included.

Data migration is idempotent at the row level via the (framework, control_id)
unique constraint: only ids not already present are inserted, so a deployment
that hand-seeded a few controls won't collide.
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "87a45499d328"
down_revision: Union[str, Sequence[str], None] = "b3c1a9f5e2d4"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


# (control_id, title, category) per framework. Titles paraphrase the official
# control text; categories group controls into the framework's own families.
_SOC2 = [
    ("CC1.1", "Demonstrates commitment to integrity and ethical values", "Control Environment"),
    ("CC1.2", "Board exercises oversight independence", "Control Environment"),
    ("CC1.3", "Establishes structures, reporting lines, and authorities", "Control Environment"),
    ("CC1.4", "Demonstrates commitment to competence", "Control Environment"),
    ("CC1.5", "Enforces accountability for responsibilities", "Control Environment"),
    ("CC2.1", "Uses relevant, quality information", "Communication & Information"),
    ("CC2.2", "Communicates information internally", "Communication & Information"),
    ("CC2.3", "Communicates with external parties", "Communication & Information"),
    ("CC3.1", "Specifies objectives to identify and assess risk", "Risk Assessment"),
    ("CC3.2", "Identifies and analyzes risk", "Risk Assessment"),
    ("CC3.3", "Considers the potential for fraud", "Risk Assessment"),
    ("CC3.4", "Identifies and assesses changes that could impact controls", "Risk Assessment"),
    ("CC4.1", "Selects and develops ongoing monitoring activities", "Monitoring Activities"),
    ("CC4.2", "Evaluates and communicates control deficiencies", "Monitoring Activities"),
    ("CC5.1", "Selects and develops control activities", "Control Activities"),
    ("CC5.2", "Develops general control activities over technology", "Control Activities"),
    ("CC5.3", "Deploys control activities through policies and procedures", "Control Activities"),
    ("CC6.1", "Implements logical access security software and architecture", "Logical & Physical Access"),
    ("CC6.2", "Registers and authorizes new internal and external users", "Logical & Physical Access"),
    ("CC6.3", "Manages access rights — provisioning, modification, removal", "Logical & Physical Access"),
    ("CC6.4", "Restricts physical access to facilities and resources", "Logical & Physical Access"),
    ("CC6.5", "Discontinues access and protections upon disposal", "Logical & Physical Access"),
    ("CC6.6", "Implements controls against threats from outside the system", "Logical & Physical Access"),
    ("CC6.7", "Restricts the transmission and movement of information", "Logical & Physical Access"),
    ("CC6.8", "Prevents and detects unauthorized or malicious software", "Logical & Physical Access"),
    ("CC7.1", "Detects configuration changes and vulnerabilities", "System Operations"),
    ("CC7.2", "Monitors system components for anomalies", "System Operations"),
    ("CC7.3", "Evaluates security events to determine impact", "System Operations"),
    ("CC7.4", "Responds to identified security incidents", "System Operations"),
    ("CC7.5", "Recovers from identified security incidents", "System Operations"),
    ("CC8.1", "Authorizes, designs, tests, and approves system changes", "Change Management"),
    ("CC9.1", "Identifies and mitigates business disruption risks", "Risk Mitigation"),
    ("CC9.2", "Assesses and manages risks from vendors and partners", "Risk Mitigation"),
]

# ISO/IEC 27001:2022 Annex A — Technological (A.8) controls plus the
# Organizational/Access controls the mapper references.
_ISO27001 = [
    ("A.5.23", "Information security for use of cloud services", "Organizational"),
    ("A.9.4", "System and application access control", "Access Control"),
    ("A.8.1", "User endpoint devices", "Technological"),
    ("A.8.2", "Privileged access rights", "Technological"),
    ("A.8.3", "Information access restriction", "Technological"),
    ("A.8.4", "Access to source code", "Technological"),
    ("A.8.5", "Secure authentication", "Technological"),
    ("A.8.6", "Capacity management", "Technological"),
    ("A.8.7", "Protection against malware", "Technological"),
    ("A.8.8", "Management of technical vulnerabilities", "Technological"),
    ("A.8.9", "Configuration management", "Technological"),
    ("A.8.10", "Information deletion", "Technological"),
    ("A.8.11", "Data masking", "Technological"),
    ("A.8.12", "Data leakage prevention", "Technological"),
    ("A.8.13", "Information backup", "Technological"),
    ("A.8.14", "Redundancy of information processing facilities", "Technological"),
    ("A.8.15", "Logging", "Technological"),
    ("A.8.16", "Monitoring activities", "Technological"),
    ("A.8.17", "Clock synchronization", "Technological"),
    ("A.8.18", "Use of privileged utility programs", "Technological"),
    ("A.8.19", "Installation of software on operational systems", "Technological"),
    ("A.8.20", "Networks security", "Technological"),
    ("A.8.21", "Security of network services", "Technological"),
    ("A.8.22", "Segregation of networks", "Technological"),
    ("A.8.23", "Web filtering", "Technological"),
    ("A.8.24", "Use of cryptography", "Technological"),
    ("A.8.25", "Secure development life cycle", "Technological"),
    ("A.8.26", "Application security requirements", "Technological"),
    ("A.8.27", "Secure system architecture and engineering principles", "Technological"),
    ("A.8.28", "Secure coding", "Technological"),
    ("A.8.29", "Security testing in development and acceptance", "Technological"),
    ("A.8.30", "Outsourced development", "Technological"),
    ("A.8.31", "Separation of development, test, and production environments", "Technological"),
    ("A.8.32", "Change management", "Technological"),
    ("A.8.33", "Test information", "Technological"),
    ("A.8.34", "Protection of information systems during audit testing", "Technological"),
]

# PCI DSS v4.0 — the 12 principal requirements plus the AppSec-relevant
# sub-requirements (including every id the mapper emits).
_PCI = [
    ("1", "Install and maintain network security controls", "Network Security"),
    ("2", "Apply secure configurations to all system components", "Secure Configuration"),
    ("3", "Protect stored account data", "Data Protection"),
    ("4", "Protect cardholder data with strong cryptography during transmission", "Data Protection"),
    ("5", "Protect all systems and networks from malicious software", "Malware Defense"),
    ("6", "Develop and maintain secure systems and software", "Secure Software"),
    ("6.2.1", "Bespoke and custom software is developed securely", "Secure Software"),
    ("6.2.4", "Software engineering techniques prevent common attacks", "Secure Software"),
    ("6.3.1", "Security vulnerabilities are identified and managed", "Secure Software"),
    ("6.3.3", "System components are protected from known vulnerabilities via patches", "Secure Software"),
    ("6.4.3", "Payment page scripts are managed and integrity-checked", "Secure Software"),
    ("7", "Restrict access to system components by business need to know", "Access Control"),
    ("8", "Identify users and authenticate access to system components", "Authentication"),
    ("8.3.6", "Passwords/passphrases meet minimum complexity requirements", "Authentication"),
    ("9", "Restrict physical access to cardholder data", "Physical Access"),
    ("10", "Log and monitor all access to system components and cardholder data", "Logging & Monitoring"),
    ("11", "Test security of systems and networks regularly", "Security Testing"),
    ("11.3.1", "Internal vulnerability scans are performed regularly", "Security Testing"),
    ("11.3.2", "External vulnerability scans are performed regularly", "Security Testing"),
    ("12", "Support information security with organizational policies and programs", "Governance"),
]

_CATALOGS = {"soc2": _SOC2, "iso27001": _ISO27001, "pci-dss": _PCI}


def upgrade() -> None:
    bind = op.get_bind()
    controls = sa.table(
        "framework_controls",
        sa.column("framework", sa.String),
        sa.column("control_id", sa.String),
        sa.column("title", sa.String),
        sa.column("description", sa.Text),
        sa.column("category", sa.String),
        sa.column("is_custom", sa.Boolean),
    )
    for framework, rows in _CATALOGS.items():
        existing = {
            r[0]
            for r in bind.execute(
                sa.text(
                    "SELECT control_id FROM framework_controls WHERE framework = :fw"
                ),
                {"fw": framework},
            )
        }
        payload = [
            {
                "framework": framework,
                "control_id": cid,
                "title": title,
                "description": None,
                "category": category,
                "is_custom": False,
            }
            for cid, title, category in rows
            if cid not in existing
        ]
        if payload:
            op.bulk_insert(controls, payload)


def downgrade() -> None:
    raise NotImplementedError("Forward-only; no downgrade.")
