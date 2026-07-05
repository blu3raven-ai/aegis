import json
import os

import pytest

from src.shared import config


def test_app_config_from_env_map_round_trips_full_shape():
    env = {
        "GITHUB_ORGS": "Example-Org,example-labs",
        "GITHUB_PAT": "fallback-token",
        "GITHUB_PAT_EXAMPLE_ORG": "primary-token",
        "GITHUB_PAT_EXAMPLE_LABS": "secondary-token",
        "ADMIN_USERNAME": "ops-admin",
        "ADMIN_PASSWORD": "secret-password",
        "SESSION_SECRET": "session-secret",
        "SCA_ENABLED": "false",
        "SAST_ENABLED": "true",
        "SAST_SCAN_CONCURRENCY": "3",
        "SAST_RULESETS": "p/owasp-top-ten,p/cwe-top-25",
        "SAST_AI_REVIEW_ENABLED": "true",
        "SAST_AI_API_KEY": "sk-test-sast-ai-key",
        "SAST_AI_BASE_URL": "https://custom.ai.api/v1",
        "SAST_AI_MODEL": "gpt-4o-custom",
        "SAST_AI_AUTO_CLASSIFY_ON_SCAN": "true",
        "SAST_AUTO_RERUN_ENABLED": "true",
        "SAST_RERUN_SCHEDULE_TYPE": "cron",
        "SAST_RERUN_SCHEDULE_VALUE": "0 2 * * *",
        "SECRETS_ENABLED": "false",
        "SECRET_SCANNER_CONCURRENCY": "7",
        "SECRETS_SCAN_CONCURRENCY": "9",
        "IAC_SECURITY_ENABLED": "false",
    }

    config_value = config.app_config_from_env_map(env)
    round_tripped = config.app_config_from_env_map(config.app_config_to_env(config_value))

    assert config_value == round_tripped
    assert config_value == {
        "dashboard": {
            "username": "ops-admin",
            "email": "",
            "password": "secret-password",
            "sessionSecret": "session-secret",
        },
        "authSecurity": {
            "requireMfaManualUsers": False,
            "requireMfaAdmins": False,
            "trustedSessionDurationDays": 30,
            "recoveryCodePolicy": "mandatory",
        },
        "tools": {
            "dependencies": {
                "enabled": False,
                "autoRerunEnabled": False,
                "rerunScheduleType": "simple",
                "rerunScheduleValue": "02:00",
                "scanConcurrency": "4",
                "nvdEnabled": True,
                "nvdApiKey": "",
                "ghsaEnabled": False,
                "ghsaApiKey": "",
            },
            "containerScanning": {
                "enabled": False,
                "autoRerunEnabled": False,
                "rerunScheduleType": "simple",
                "rerunScheduleValue": "02:00",
                "scanConcurrency": "4",
                "nvdEnabled": True,
                "nvdApiKey": "",
                "ghsaEnabled": False,
                "ghsaApiKey": "",
                "argusEnabled": False,
                "argusApiKey": "",
            },
            "codeScanning": {
                "enabled": True,
                "scanConcurrency": "3",
                "rulesets": ["p/owasp-top-ten", "p/cwe-top-25"],
                "autoRerunEnabled": True,
                "rerunScheduleType": "cron",
                "rerunScheduleValue": "0 2 * * *",
            },
            "secrets": {
                "enabled": False,
                "scanConcurrency": "7",
                "scanDepth": "light",
                "scanHistoryWindow": "all",
                "aiReviewEnabled": False,
                "aiApiKey": "",
                "autoRerunEnabled": False,
                "rerunScheduleType": "simple",
                "rerunScheduleValue": "02:00",
            },
            "iacSecurity": {
                "enabled": False,
            },
        },
    }


def test_env_source_preserves_env_file_override_semantics(tmp_path, monkeypatch):
    env_path = tmp_path / ".env.local"
    env_path.write_text(
        "GITHUB_ORG=from-file\n"
        "GITHUB_PAT=from-file-token\n"
        "ADMIN_USERNAME=file-admin\n",
        encoding="utf-8",
    )

    monkeypatch.setattr(config, "ENV_PATH", env_path)
    # Process env overrides file values (env_source = {**file, **os.environ})
    monkeypatch.setenv("GITHUB_ORG", "from-process")
    monkeypatch.setenv("GITHUB_PAT", "from-process-token")
    # Remove ADMIN_USERNAME from process env so the file value is used
    monkeypatch.delenv("ADMIN_USERNAME", raising=False)

    source = config.env_source()

    # Process env wins over file
    assert source["GITHUB_ORG"] == "from-process"
    assert source["GITHUB_PAT"] == "from-process-token"
    # File value used when not in process env
    assert source["ADMIN_USERNAME"] == "file-admin"


def test_write_app_config_persists_to_db_and_records_audit_event():
    """write_app_config stores config in the AppConfig table and records an audit event."""
    config_value = {
        "dashboard": {
            "username": "ops-admin",
            "password": "secret-password",
            "sessionSecret": "session-secret",
        },
        "tools": {
            "dependencies": {
                "enabled": True,
            },
            "codeScanning": {
                "enabled": False,
                "scanConcurrency": "2",
                "rulesets": ["p/owasp-top-ten", "p/cwe-top-25"],
                "autoRerunEnabled": False,
                "rerunScheduleType": "simple",
                "rerunScheduleValue": "02:00",
            },
            "secrets": {
                "enabled": True,
                "scanConcurrency": "4",
            },
            "iacSecurity": {
                "enabled": False,
            },
        },
    }

    config.write_app_config(config_value, "settings.updated")

    # Verify config was persisted to DB
    from src.db.helpers import run_db
    from src.db.models import AppConfig

    async def _read(session):
        row = await session.get(AppConfig, 1)
        return row.config if row else None

    saved = run_db(_read)
    assert saved == config_value

    # Verify audit event was recorded
    from sqlalchemy import select
    from src.db.models import AuditEvent

    async def _read_audit(session):
        result = await session.execute(
            select(AuditEvent)
            .where(AuditEvent.action == "settings.updated")
            .order_by(AuditEvent.id.desc())
            .limit(1)
        )
        return result.scalars().first()

    event = run_db(_read_audit)
    assert event is not None
    assert event.action == "settings.updated"
    # Password/sessionSecret should be redacted in the audit metadata
    meta = event.metadata_json
    assert meta["dashboard"]["password"] == "[redacted]"
    assert meta["dashboard"]["sessionSecret"] == "[redacted]"


def test_sync_runtime_env_from_config_sets_values_and_removes_keys(monkeypatch):
    monkeypatch.setenv("OLD_RUNTIME_KEY", "stale")
    monkeypatch.setenv("GITHUB_ORG", "old-org")

    config_value = {
        "dashboard": {
            "username": "ops-admin",
            "password": "secret-password",
            "sessionSecret": "session-secret",
        },
        "tools": {
            "codeScanning": {
                "enabled": True,
                "scanConcurrency": "3",
                "rulesets": ["p/owasp-top-ten", "p/cwe-top-25"],
                "autoRerunEnabled": True,
                "rerunScheduleType": "cron",
                "rerunScheduleValue": "0 3 * * *",
            },
            "secrets": {
                "enabled": False,
                "scanConcurrency": "6",
            },
            "iacSecurity": {
                "enabled": True,
            },
        },
    }

    config.sync_runtime_env_from_config(config_value, removed_keys=["OLD_RUNTIME_KEY"])

    assert os.environ["ADMIN_USERNAME"] == "ops-admin"
    assert os.environ["ADMIN_PASSWORD"] == "secret-password"
    assert os.environ["SESSION_SECRET"] == "session-secret"
    assert os.environ["SAST_ENABLED"] == "true"
    assert os.environ["SAST_SCAN_CONCURRENCY"] == "3"
    assert os.environ["SAST_RULESETS"] == "p/owasp-top-ten,p/cwe-top-25"
    assert os.environ["SAST_AUTO_RERUN_ENABLED"] == "true"
    assert os.environ["SAST_RERUN_SCHEDULE_TYPE"] == "cron"
    assert os.environ["SAST_RERUN_SCHEDULE_VALUE"] == "0 3 * * *"
    assert os.environ["SECRETS_ENABLED"] == "false"
    assert os.environ["SECRET_SCANNER_CONCURRENCY"] == "6"
    assert os.environ["IAC_SECURITY_ENABLED"] == "true"
    assert os.environ["SECRETS_SCAN_CONCURRENCY"] == "6"
    assert os.environ["SECRETS_AUTO_RERUN_ENABLED"] == "false"
    assert os.environ["SECRETS_RERUN_SCHEDULE_TYPE"] == "simple"
    assert os.environ["SECRETS_RERUN_SCHEDULE_VALUE"] == "02:00"
    assert "OLD_RUNTIME_KEY" not in os.environ


def test_default_permission_catalog_includes_manage_roles_and_manage_access_scope():
    from src.settings.roles_store import BUILTIN_PERMISSION_IDS

    assert "manage_roles" in BUILTIN_PERMISSION_IDS
    assert "manage_access_scope" in BUILTIN_PERMISSION_IDS
    assert "manage_sources" in BUILTIN_PERMISSION_IDS


def test_app_config_from_env_has_no_org_scope():
    from src.shared.config import app_config_from_env_map

    config = app_config_from_env_map({})
    for tool_name in ("codeScanning", "secrets", "iacSecurity"):
        tool = config["tools"][tool_name]
        assert "orgScope" not in tool, f"{tool_name} still has orgScope"
        assert "orgs" not in tool, f"{tool_name} still has orgs"


def test_app_config_to_env_has_no_org_scope_vars():
    from src.shared.config import app_config_from_env_map, app_config_to_env

    config = app_config_from_env_map({})
    env = app_config_to_env(config)
    org_scope_keys = [k for k in env if "ORG_SCOPE" in k or (k.endswith("_ORGS") and not k.startswith("DASHBOARD"))]
    assert org_scope_keys == [], f"Env still exports org scope vars: {org_scope_keys}"
