"""Static connector catalog — source of truth for what the UI renders."""
from __future__ import annotations
from dataclasses import dataclass, field


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
    category: str            # "notifications" | "ticketing" | "cicd" | "automation"
    icon_slug: str           # matched to icon in FE
    enterprise_only: bool
    config_fields: list[ConfigField]
    docs_url: str = ""


CATALOG: list[ConnectorType] = [
    # ── Notifications ────────────────────────────────────────────────────────
    ConnectorType(
        id="slack",
        name="Slack",
        description="Send security alerts to Slack channels.",
        category="notifications",
        icon_slug="slack",
        enterprise_only=False,
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
        enterprise_only=False,
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
        enterprise_only=True,
        config_fields=[
            ConfigField("token", "Personal access token", "password", secret=True),
            ConfigField("repo", "Target repo (org/repo)", "text", placeholder="acme-org/security-issues"),
        ],
    ),
    # ── CI/CD ────────────────────────────────────────────────────────────────
    ConnectorType(
        id="github_actions",
        name="GitHub Actions",
        description="Trigger GitHub Actions workflows on scan completion.",
        category="cicd",
        icon_slug="github",
        enterprise_only=True,
        config_fields=[
            ConfigField("token", "Personal access token", "password", secret=True),
            ConfigField("repo", "Workflow repo (org/repo)", "text"),
            ConfigField("workflow_id", "Workflow file name", "text", placeholder="security-gate.yml"),
        ],
    ),
    ConnectorType(
        id="gitlab_ci",
        name="GitLab CI",
        description="Trigger GitLab CI pipelines on scan completion.",
        category="cicd",
        icon_slug="gitlab",
        enterprise_only=True,
        config_fields=[
            ConfigField("token", "Project access token", "password", secret=True),
            ConfigField("project_id", "Project ID", "text"),
        ],
    ),
    ConnectorType(
        id="jenkins",
        name="Jenkins",
        description="Trigger Jenkins jobs when critical findings are detected.",
        category="cicd",
        icon_slug="jenkins",
        enterprise_only=True,
        config_fields=[
            ConfigField("url", "Jenkins base URL", "url"),
            ConfigField("job_name", "Job name", "text"),
            ConfigField("token", "API token", "password", secret=True),
        ],
    ),
    # ── Automation ───────────────────────────────────────────────────────────
    ConnectorType(
        id="webhook",
        name="Webhooks",
        description="POST finding events to any HTTP endpoint.",
        category="automation",
        icon_slug="webhook",
        enterprise_only=False,
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
        enterprise_only=False,
        config_fields=[],
    ),
]

CATALOG_BY_ID: dict[str, ConnectorType] = {c.id: c for c in CATALOG}
