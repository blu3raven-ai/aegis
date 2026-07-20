"""seed default compliance frameworks

Revision ID: b36d93a0cb9e
Revises: d3b8f1a05e27
Create Date: 2026-07-18 20:39:56.963060

Seeds SOC 2, ISO/IEC 27001, and PCI DSS alongside the OWASP LLM framework so
the compliance surface is populated out of the box. Control ids match the
identifiers the finding auto-mapper emits, so existing mappings attach on seed.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'b36d93a0cb9e'
down_revision: Union[str, Sequence[str], None] = 'd3b8f1a05e27'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


# (id, label, description) per framework.
_FRAMEWORKS = [
    (
        "soc2",
        "SOC 2 (Trust Services Criteria)",
        "AICPA Trust Services Criteria common controls covering logical access and system operations.",
    ),
    (
        "iso27001",
        "ISO/IEC 27001 (Annex A)",
        "Selected Annex A controls covering cloud usage, vulnerability, and configuration management.",
    ),
    (
        "pci-dss",
        "PCI DSS v4.0",
        "Selected requirements covering secure development, vulnerability management, and authentication.",
    ),
]

# framework_id -> list of (control_id, title, description, category).
_CONTROLS: dict[str, list[tuple[str, str, str, str]]] = {
    "soc2": [
        ("CC6.1", "Logical access controls",
         "Software, infrastructure, and architectures implement logical access controls to protect information assets.",
         "Logical & Physical Access"),
        ("CC6.6", "Boundary protection",
         "Logical access security measures protect against threats from sources outside the system boundaries.",
         "Logical & Physical Access"),
        ("CC6.7", "Restricting information movement",
         "Transmission, movement, and removal of information is restricted to authorized users and processes.",
         "Logical & Physical Access"),
        ("CC6.8", "Malicious software prevention",
         "Controls prevent or detect and act upon the introduction of unauthorized or malicious software.",
         "Logical & Physical Access"),
        ("CC7.1", "Vulnerability detection",
         "Detection and monitoring procedures identify changes and vulnerabilities in system configurations.",
         "System Operations"),
        ("CC7.2", "Security event monitoring",
         "System components are monitored for anomalies indicative of malicious acts, errors, and incidents.",
         "System Operations"),
    ],
    "iso27001": [
        ("A.5.23", "Information security for cloud services",
         "Acquisition, use, management, and exit from cloud services follow information security requirements.",
         "Organizational Controls"),
        ("A.8.8", "Management of technical vulnerabilities",
         "Information about technical vulnerabilities is obtained, exposure evaluated, and appropriate measures taken.",
         "Technological Controls"),
        ("A.8.9", "Configuration management",
         "Configurations of hardware, software, services, and networks are established, documented, and monitored.",
         "Technological Controls"),
        ("A.9.4", "System and application access control",
         "Access to information and application system functions is restricted in line with the access control policy.",
         "Access Control"),
    ],
    "pci-dss": [
        ("6.2.4", "Secure software engineering",
         "Software engineering techniques prevent or mitigate common software attacks in bespoke and custom software.",
         "Develop & Maintain Secure Systems"),
        ("6.3.1", "Identifying security vulnerabilities",
         "Security vulnerabilities are identified, assigned a risk ranking, and tracked to resolution.",
         "Develop & Maintain Secure Systems"),
        ("6.3.3", "Patching known vulnerabilities",
         "System components are protected from known vulnerabilities by installing applicable security patches.",
         "Develop & Maintain Secure Systems"),
        ("8.3.6", "Authentication credential strength",
         "Passwords and passphrases meet minimum strength and are protected during transmission and storage.",
         "Identify & Authenticate Access"),
        ("11.3.1", "Internal vulnerability scans",
         "Internal vulnerability scans are performed regularly and identified vulnerabilities are resolved.",
         "Test Security of Systems"),
    ],
}


def upgrade() -> None:
    framework_stmt = sa.text(
        """
        INSERT INTO frameworks (id, label, description, is_custom, created_at, updated_at)
        VALUES (:id, :label, :descr, false, now(), now())
        ON CONFLICT (id) DO NOTHING
        """
    )
    control_stmt = sa.text(
        """
        INSERT INTO framework_controls (framework, control_id, title, description, category, is_custom, created_at)
        VALUES (:fw, :cid, :title, :descr, :cat, false, now())
        ON CONFLICT (framework, control_id) DO NOTHING
        """
    )
    for framework_id, label, descr in _FRAMEWORKS:
        op.execute(framework_stmt.bindparams(id=framework_id, label=label, descr=descr))
        for control_id, title, control_descr, category in _CONTROLS[framework_id]:
            op.execute(
                control_stmt.bindparams(
                    fw=framework_id, cid=control_id, title=title, descr=control_descr, cat=category
                )
            )


def downgrade() -> None:
    raise NotImplementedError("Forward-only; no downgrade.")
