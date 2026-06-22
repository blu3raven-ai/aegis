"""Static connector catalog — source of truth for what the UI renders."""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Literal

ConnectorStatus = Literal["stable", "beta", "preview", "deprecated"]


@dataclass
class ConfigField:
    name: str
    label: str
    field_type: str          # "text" | "url" | "password" | "select"
    required: bool = True
    placeholder: str = ""
    options: list[str] = field(default_factory=list)   # for select type
    secret: bool = False     # mask in UI and store encrypted


@dataclass
class ConnectorType:
    id: str                  # stable snake_case key — used as destination_type in DB
    name: str
    description: str
    category: str            # "cicd" | "notifications" | "ticketing" | "automation" | "runner"
    icon_slug: str
    version: str             # owned per-entry — bump manually when promoting
    status: ConnectorStatus  # owned per-entry — promote per integration as it stabilises
    enterprise_only: bool = False
    config_fields: list[ConfigField] = field(default_factory=list)
    docs_url: str = ""
    href: str | None = None  # external setup URL, when not handled by inline config_fields


CATALOG: list[ConnectorType] = [
    # ── CI/CD (inbound: trigger scans from CI) ───────────────────────────────
    ConnectorType(
        id="github-action",
        name="GitHub Action",
        description="Trigger scans on push and pull request from GitHub Actions",
        category="cicd",
        icon_slug="github",
        version="v0.1.0",
        status="beta",
    ),
    ConnectorType(
        id="gitlab-component",
        name="GitLab CI Component",
        description="Trigger scans on push and merge request from GitLab CI",
        category="cicd",
        icon_slug="gitlab",
        version="v0.1.0",
        status="beta",
    ),
    ConnectorType(
        id="bitbucket-pipe",
        name="Bitbucket Pipe",
        description="Trigger scans on push and pull request from Bitbucket Pipelines",
        category="cicd",
        icon_slug="bitbucket",
        version="v0.1.0",
        status="beta",
    ),
    ConnectorType(
        id="azure-devops-task",
        name="Azure DevOps Task",
        description="Trigger scans on PR and build from Azure Pipelines",
        category="cicd",
        icon_slug="azuredevops",
        version="v0.1.0",
        status="beta",
    ),
    ConnectorType(
        id="jenkins-shared-library",
        name="Jenkins Shared Library",
        description="Trigger scans from your Jenkins pipeline",
        category="cicd",
        icon_slug="jenkins",
        version="v0.1.0",
        status="beta",
    ),
    # ── Notifications ────────────────────────────────────────────────────────
    ConnectorType(
        id="slack",
        name="Slack",
        description="Send security alerts to Slack channels.",
        category="notifications",
        icon_slug="slack",
        version="v0.1.0",
        status="beta",
        config_fields=[
            ConfigField("webhook_url", "Webhook URL", "url", placeholder="https://hooks.slack.com/…", secret=True),
            ConfigField("channel", "Default channel", "text", required=False, placeholder="#security-alerts"),
        ],
    ),
    ConnectorType(
        id="microsoft_teams",
        name="Microsoft Teams",
        description="Send security alerts to Teams channels.",
        category="notifications",
        icon_slug="microsoft_teams",
        version="v0.1.0",
        status="beta",
        enterprise_only=True,
        config_fields=[
            ConfigField("webhook_url", "Incoming webhook URL", "url", secret=True),
        ],
    ),
    ConnectorType(
        id="pagerduty",
        name="PagerDuty",
        description="Trigger PagerDuty incidents for critical findings.",
        category="notifications",
        icon_slug="pagerduty",
        version="v0.1.0",
        status="beta",
        enterprise_only=True,
        config_fields=[
            ConfigField("integration_key", "Integration key", "password", secret=True),
            ConfigField("severity_threshold", "Minimum severity", "select", options=["critical", "high", "medium"]),
        ],
    ),
    ConnectorType(
        id="email_digest",
        name="Email Digest",
        description="Weekly email digest of open findings.",
        category="notifications",
        icon_slug="email",
        version="v0.1.0",
        status="beta",
        config_fields=[
            ConfigField("to", "Recipients", "text", placeholder="alice@example.com, bob@example.com"),
        ],
    ),
    # ── Ticketing ────────────────────────────────────────────────────────────
    ConnectorType(
        id="jira",
        name="Jira",
        description="Auto-create Jira tickets for new critical and high findings.",
        category="ticketing",
        icon_slug="jira",
        version="v0.1.0",
        status="beta",
        enterprise_only=True,
        config_fields=[
            ConfigField("base_url", "Jira base URL", "url", placeholder="https://acme.atlassian.net"),
            ConfigField("api_token", "API token", "password", secret=True),
            ConfigField("email", "Account email", "text"),
            ConfigField("project_key", "Project key", "text", placeholder="SEC"),
            ConfigField("issue_type", "Issue type", "text", placeholder="Bug"),
        ],
    ),
    ConnectorType(
        id="linear",
        name="Linear",
        description="Auto-create Linear issues for security findings.",
        category="ticketing",
        icon_slug="linear",
        version="v0.1.0",
        status="beta",
        enterprise_only=True,
        config_fields=[
            ConfigField("api_key", "API key", "password", secret=True),
            ConfigField("team_id", "Team ID", "text"),
        ],
    ),
    ConnectorType(
        id="github_issues",
        name="GitHub Issues",
        description="Open GitHub issues for critical findings in monitored repos.",
        category="ticketing",
        icon_slug="github",
        version="v0.1.0",
        status="beta",
        enterprise_only=True,
        config_fields=[
            ConfigField("token", "Personal access token", "password", secret=True),
            ConfigField("repo", "Target repo (org/repo)", "text", placeholder="acme-org/security-issues"),
        ],
    ),
    # ── Automation ───────────────────────────────────────────────────────────
    ConnectorType(
        id="webhook",
        name="Webhooks",
        description="POST finding events to any HTTP endpoint.",
        category="automation",
        icon_slug="webhook",
        version="v0.1.0",
        status="beta",
        config_fields=[
            ConfigField("url", "Endpoint URL", "url", secret=False),
            ConfigField("secret", "Signing secret", "password", required=False, secret=True),
        ],
    ),
    ConnectorType(
        id="api_keys",
        name="API Keys",
        description="Programmatic access via REST API.",
        category="automation",
        icon_slug="key",
        version="v0.1.0",
        status="beta",
    ),
    # ── Runner ───────────────────────────────────────────────────────────────
    ConnectorType(
        id="federated-runner",
        name="Federated Runner",
        description="Run scans privately on your own infrastructure",
        category="runner",
        icon_slug="runner",
        version="v0.1.0",
        status="beta",
        href="/settings/runners",
    ),
]

CATALOG_BY_ID: dict[str, ConnectorType] = {c.id: c for c in CATALOG}
