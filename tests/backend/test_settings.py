import json
import base64
import hashlib
import hmac
import time

import pytest
from fastapi.testclient import TestClient

import src.shared.config as config
import src.settings.router as settings_router
from src.main import app


@pytest.fixture(scope="session", autouse=True)
def _seed_roles():
    """Ensure the default roles exist in the DB for the entire test session."""
    from src.db.helpers import run_db
    from src.db.models import Role
    from src.db.seed import DEFAULT_ROLES
    from datetime import datetime, timezone

    async def _insert(session):
        for role_data in DEFAULT_ROLES:
            existing = await session.get(Role, role_data["id"])
            if not existing:
                session.add(Role(
                    id=role_data["id"],
                    name=role_data["name"],
                    description=role_data["description"],
                    permissions=role_data["permissions"],
                    protected=role_data["protected"],
                    created_at=datetime.now(timezone.utc),
                ))

    run_db(_insert)


@pytest.fixture
def isolated_config(tmp_path, monkeypatch):
    env_path = tmp_path / ".env.local"

    monkeypatch.setattr(config, "ENV_PATH", env_path)

    monkeypatch.setenv("JWT_SHARED_SECRET", "a" * 64)

    for key in [
        "GITHUB_ORG",
        "GITHUB_ORGS",
        "GITHUB_PAT",
        "GITHUB_PAT_EXAMPLE_ORG",
        "GITHUB_PAT_EXAMPLE_LABS",
        "GITHUB_PAT_OLD_ORG",
        "ADMIN_USERNAME",
        "ADMIN_EMAIL",
        "ADMIN_PASSWORD",
        "SESSION_SECRET",
        "AUTH_SECURITY_REQUIRE_MFA_MANUAL",
        "AUTH_SECURITY_REQUIRE_MFA_ADMINS",
        "AUTH_SECURITY_TRUSTED_SESSION_DURATION",
        "AUTH_SECURITY_RECOVERY_CODE_POLICY",
        "SCA_ENABLED",
        "SCA_AUTO_RERUN_ENABLED",
        "SCA_RERUN_SCHEDULE_TYPE",
        "SCA_RERUN_SCHEDULE_VALUE",
        "SCA_DEFAULT_PER_PAGE",
        "SAST_ENABLED",
        "SAST_AUTO_REFRESH_SECONDS",
        "SAST_DEFAULT_SOURCE",
        "SAST_AUTO_RERUN_ENABLED",
        "SAST_RERUN_SCHEDULE_TYPE",
        "SAST_RERUN_SCHEDULE_VALUE",
        "SECRETS_ENABLED",
        "SECRET_SCANNER_CONCURRENCY",
        "SECRETS_SCAN_CONCURRENCY",
        "SECRET_SCANNER_IMAGE",
        "SECRETS_AI_REVIEW_ENABLED",
        "SECRETS_AI_API_KEY",
        "SECRETS_AI_BASE_URL",
        "SECRETS_AI_MODEL",
        "SECRETS_AUTO_RERUN_ENABLED",
        "SECRETS_RERUN_SCHEDULE_TYPE",
        "SECRETS_RERUN_SCHEDULE_VALUE",
        "IAC_SECURITY_ENABLED",
    ]:
        monkeypatch.delenv(key, raising=False)


@pytest.fixture
def client():
    c = TestClient(app)
    # Default to admin auth so tests don't need to pass headers for every call
    c.headers.update(_auth_headers("admin"))
    return c


def _b64url(data: bytes | str) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("utf-8")


def _make_jwt(sub: str, role: str, secret: str, role_id: str | None = None) -> str:
    now = int(time.time())
    header = _b64url(json.dumps({"alg": "HS256", "typ": "JWT"}))
    payload_data = {"sub": sub, "role": role, "iat": now, "exp": now + 60}
    if role_id:
        payload_data["roleId"] = role_id
    payload = _b64url(json.dumps(payload_data))
    key = bytes.fromhex(secret)
    signature = _b64url(hmac.new(key, f"{header}.{payload}".encode("utf-8"), hashlib.sha256).digest())
    return f"{header}.{payload}.{signature}"


def _auth_headers(role: str, secret: str = "a" * 64, role_id: str | None = None) -> dict[str, str]:
    return {"Authorization": f"Bearer {_make_jwt(sub=f'usr_{role}', role=role, secret=secret, role_id=role_id)}"}


def _read_last_audit_event(action: str) -> dict | None:
    """Read the most recent audit event with the given action from the DB."""
    from src.db.helpers import run_db
    from src.db.models import AuditEvent
    from sqlalchemy import select

    async def _query(session):
        result = await session.execute(
            select(AuditEvent)
            .where(AuditEvent.action == action)
            .order_by(AuditEvent.id.desc())
            .limit(1)
        )
        row = result.scalars().first()
        if not row:
            return None
        return {"action": row.action, "metadata": row.metadata_json}

    return run_db(_query)


def test_get_settings_returns_current_config_without_dashboard_secrets(client, isolated_config):
    config.write_app_config(
        {
            "github": {
                "orgs": [
                    {"name": "Example-Org", "token": "primary-token"},
                ]
            },
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
                    "enabled": True,
                    "autoRefreshSeconds": "120",
                    "source": "github-code-scanning",
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
    )

    response = client.get("/settings/api", headers=_auth_headers("admin"))
    assert response.status_code == 200
    payload = response.json()
    assert payload["dashboard"] == {
        "username": "ops-admin",
        "email": "",
        "password": "",
        "sessionSecret": "",
    }
    # github section is no longer part of the normalized config returned by the API
    assert "github" not in payload


def test_get_settings_backfills_new_settings_sections_for_legacy_config(client, isolated_config):
    config.write_app_config(
        {
            "github": {
                "orgs": [
                    {"name": "Example-Org", "token": "primary-token"},
                ]
            },
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
                    "enabled": True,
                    "autoRefreshSeconds": "120",
                    "source": "github-code-scanning",
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
    )

    response = client.get("/settings/api")

    assert response.status_code == 200
    payload = response.json()
    assert payload["authSecurity"] == {
        "requireMfaManualUsers": False,
        "requireMfaAdmins": False,
        "trustedSessionDurationDays": 30,
        "recoveryCodePolicy": "mandatory",
    }


def test_get_settings_rejects_non_admin_users(client, isolated_config, monkeypatch):
    config.write_app_config(
        {
            "github": {"orgs": [{"name": "Example-Org", "token": "primary-token"}]},
            "dashboard": {
                "username": "ops-admin",
                "password": "secret-password",
                "sessionSecret": "session-secret",
            },
            "tools": {},
        }
    )
    secret = "a" * 64
    monkeypatch.setenv("FASTAPI_ENV", "production")
    monkeypatch.setenv("JWT_SHARED_SECRET", secret)

    response = client.get("/settings/api", headers=_auth_headers("viewer", secret))

    assert response.status_code == 403


def test_patch_tool_settings_rejects_non_admin_users(client, isolated_config, monkeypatch):
    secret = "a" * 64
    monkeypatch.setenv("FASTAPI_ENV", "production")
    monkeypatch.setenv("JWT_SHARED_SECRET", secret)
    config.write_app_config(
        {
            "github": {"orgs": []},
            "dashboard": {"username": "admin", "password": "pw", "sessionSecret": secret},
            "tools": {
                "secrets": {
                    "enabled": False,
                    "dockerImage": "github-secrets",
                },
            },
        }
    )

    response = client.patch(
        "/settings/api/tools/secrets",
        headers=_auth_headers("viewer", secret),
        json={
            "enabled": True,
            "settings": {
                "scanConcurrency": "4",
                "dockerImage": "github-secrets",
            },
        },
    )

    assert response.status_code == 403


@pytest.mark.asyncio
async def test_patch_general_updates_username_and_syncs_runtime_env(
    client, isolated_config, monkeypatch
):
    config.write_app_config(
        {
            "github": {
                "orgs": [
                    {"name": "old-org", "token": "old-token"},
                ]
            },
            "dashboard": {
                "username": "old-admin",
                "password": "current-password",
                "sessionSecret": "existing-session-secret",
            },
            "tools": {
                "dependencies": {
                    "enabled": True,
                },
                "codeScanning": {
                    "enabled": True,
                    "autoRefreshSeconds": "120",
                    "source": "github-code-scanning",
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
    )

    response = client.patch(
        "/settings/api/general",
        json={
            "orgs": [],
            "username": "ops-admin",
        },
    )

    assert response.status_code == 200
    assert response.json() == {"ok": True}

    updated = config.read_app_config()
    assert updated["dashboard"]["username"] == "ops-admin"

    event = _read_last_audit_event("settings.general.updated")
    assert event is not None


@pytest.mark.asyncio
async def test_patch_account_rejects_wrong_current_password(client, isolated_config):
    config.write_app_config(
        {
            "github": {"orgs": []},
            "dashboard": {
                "username": "ops-admin",
                "password": "current-password",
                "sessionSecret": "existing-session-secret",
            },
            "tools": {
                "dependencies": {
                    "enabled": True,
                },
                "codeScanning": {
                    "enabled": True,
                    "autoRefreshSeconds": "120",
                    "source": "github-code-scanning",
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
    )

    response = client.patch(
        "/settings/api/account",
        json={
            "username": "ops-admin",
            "current_password": "wrong-password",
            "new_password": "new-password",
            "confirm_new_password": "new-password",
        },
    )

    assert response.status_code == 400
    assert response.json() == {"detail": "Current password is incorrect."}


@pytest.mark.asyncio
async def test_patch_account_updates_username_and_password(client, isolated_config):
    config.write_app_config(
        {
            "github": {"orgs": []},
            "dashboard": {
                "username": "ops-admin",
                "password": "current-password",
                "sessionSecret": "",
            },
            "tools": {
                "dependencies": {
                    "enabled": True,
                },
                "codeScanning": {
                    "enabled": True,
                    "autoRefreshSeconds": "120",
                    "source": "github-code-scanning",
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
    )

    response = client.patch(
        "/settings/api/account",
        json={
            "username": "security-admin",
            "current_password": "current-password",
            "new_password": "new-password",
            "confirm_new_password": "new-password",
        },
    )

    assert response.status_code == 200
    assert response.json() == {"ok": True}

    saved = config.read_app_config()
    assert saved["dashboard"]["username"] == "security-admin"
    # Password is now hashed (scrypt format)
    assert saved["dashboard"]["password"].startswith("scrypt:v1:")
    assert saved["dashboard"]["sessionSecret"]

    event = _read_last_audit_event("settings.account.updated")
    assert event is not None


@pytest.mark.parametrize(
    ("tool", "payload", "expected_keys"),
    [
        (
            "dependencies",
            {
                "enabled": False,
                    "settings": {
                    "autoRerunEnabled": "false",
                    "rerunScheduleType": "simple",
                    "rerunScheduleValue": "02:00",
                },
            },
            {
                "enabled": False,
                "autoRerunEnabled": False,
                "rerunScheduleType": "simple",
                "rerunScheduleValue": "02:00",
            },
        ),
        (
            "codeScanning",
            {
                "enabled": True,
                    "settings": {
                    "autoRefreshSeconds": "300",
                    "source": "semgrep",
                    "autoRerunEnabled": "false",
                    "rerunScheduleType": "simple",
                    "rerunScheduleValue": "02:00",
                },
            },
            {
                "enabled": True,
                "autoRerunEnabled": False,
                "rerunScheduleType": "simple",
                "rerunScheduleValue": "02:00",
            },
        ),
        (
            "secrets",
            {
                "enabled": True,
                    "settings": {
                    "scanConcurrency": "8",
                    "dockerImage": "should-be-ignored",
                    "aiReviewEnabled": "true",
                    "aiApiKey": "sk-new-key",
                    "aiBaseUrl": "https://api.openai.com/v1",
                    "aiModelName": "gpt-4o-mini",
                    "autoRerunEnabled": "false",
                    "rerunScheduleType": "simple",
                    "rerunScheduleValue": "02:00",
                },
            },
            {
                "aiApiKey": "sk-new-key",
                "aiReviewEnabled": True,
                "dockerImage": "aegis/scanner-secrets:latest",
                "enabled": True,
                "scanConcurrency": "8",
                "autoRerunEnabled": False,
                "rerunScheduleType": "simple",
                "rerunScheduleValue": "02:00",
            },
        ),
        (
            "iacSecurity",
            {
                "enabled": False,
                    "settings": {
                    "autoRerunEnabled": "false",
                    "rerunScheduleType": "simple",
                    "rerunScheduleValue": "02:00",
                },
            },
            {
                "enabled": False,
            },
        ),
    ],
)
def test_patch_tool_settings_persists_tool_config(client, isolated_config, monkeypatch, tool, payload, expected_keys):
    # Mock prerequisites to pass (no runner online in tests)
    from src.settings.schemas import ScannerPrerequisitesResponse
    monkeypatch.setattr(
        "src.settings.router._runner_based_prerequisites",
        lambda tool: ScannerPrerequisitesResponse(docker_image_present=True, signature_valid=True),
    )
    config.write_app_config(
        {
            "github": {
                "orgs": [
                    {"name": "Example-Org", "token": "primary-token"},
                    {"name": "Example-Labs", "token": "secondary-token"},
                ]
            },
            "dashboard": {
                "username": "ops-admin",
                "password": "current-password",
                "sessionSecret": "existing-session-secret",
            },
            "tools": {
                "dependencies": {
                    "enabled": True,
                },
                "codeScanning": {
                    "enabled": True,
                    "autoRefreshSeconds": "120",
                    "source": "github-code-scanning",
                },
                "secrets": {
                    "enabled": False,
                    "scanConcurrency": "4",
                },
                "iacSecurity": {
                    "enabled": False,
                },
            },
        }
    )

    response = client.patch(f"/settings/api/tools/{tool}", json=payload)

    assert response.status_code == 200
    assert response.json() == {"ok": True}

    saved = config.read_app_config()
    saved_tool = saved["tools"][tool]
    for key, expected_value in expected_keys.items():
        assert saved_tool[key] == expected_value, f"{tool}.{key}: {saved_tool[key]!r} != {expected_value!r}"

    if tool == "secrets":
        assert config.get_app_config_env_value("SECRET_SCANNER_CONCURRENCY") == "8"
        assert config.get_app_config_env_value("SECRETS_SCAN_CONCURRENCY") == "8"


def test_patch_secrets_enables_without_docker_check(client, isolated_config, monkeypatch):
    """Scanner tools can be enabled when prerequisites pass."""
    from src.settings.schemas import ScannerPrerequisitesResponse
    monkeypatch.setattr(
        "src.settings.router._runner_based_prerequisites",
        lambda tool: ScannerPrerequisitesResponse(docker_image_present=True, signature_valid=True),
    )
    secret = "a" * 64
    monkeypatch.setenv("JWT_SHARED_SECRET", secret)
    config.write_app_config(
        {
            "github": {
                "orgs": [
                    {"name": "Example-Org", "token": "primary-token"},
                ]
            },
            "dashboard": {
                "username": "ops-admin",
                "password": "current-password",
                "sessionSecret": secret,
            },
            "tools": {
                "secrets": {
                    "enabled": False,
                    "scanConcurrency": "4",
                },
            },
        }
    )

    response = client.patch(
        "/settings/api/tools/secrets",
        headers=_auth_headers("admin", secret),
        json={
            "enabled": True,
            "settings": {
                "scanConcurrency": "4",
            },
        },
    )

    assert response.status_code == 200
    saved = config.read_app_config()
    assert saved["tools"]["secrets"]["enabled"] is True


def test_patch_secrets_stores_ai_settings_when_provided(client, isolated_config, monkeypatch):
    from src.settings.schemas import ScannerPrerequisitesResponse
    monkeypatch.setattr(
        "src.settings.router._runner_based_prerequisites",
        lambda tool: ScannerPrerequisitesResponse(docker_image_present=True, signature_valid=True),
    )
    secret = "a" * 64
    monkeypatch.setenv("JWT_SHARED_SECRET", secret)
    config.write_app_config(
        {
            "github": {"orgs": []},
            "dashboard": {"username": "admin", "password": "pw", "sessionSecret": secret},
            "tools": {
                "secrets": {
                    "enabled": False,
                    "scanConcurrency": "4",
                    "dockerImage": "aegis/scanner-secrets:latest",
                },
            },
        }
    )

    # Secrets AI settings are stored without server-side validation
    # (unlike SAST which validates aiBaseUrl/aiModelName/aiApiKey)
    response = client.patch(
        "/settings/api/tools/secrets",
        headers=_auth_headers("admin", secret),
        json={
            "enabled": True,
            "settings": {
                "scanConcurrency": "4",
                "aiReviewEnabled": "true",
                "aiApiKey": "sk-test",
                "aiBaseUrl": "https://api.openai.com/v1",
                "aiModelName": "gpt-4o-mini",
            },
        },
    )
    assert response.status_code == 200

    saved = config.read_app_config()
    assert saved["tools"]["secrets"]["aiReviewEnabled"] is True
    assert saved["tools"]["secrets"]["aiApiKey"] == "sk-test"




@pytest.mark.asyncio
async def test_get_rate_limit_uses_org_token_and_normalizes_response(client, isolated_config, monkeypatch):
    import src.settings.router as settings_router

    config.write_app_config(
        {
            "github": {"orgs": []},
            "dashboard": {
                "username": "ops-admin",
                "password": "current-password",
                "sessionSecret": "existing-session-secret",
            },
            "tools": {},
        }
    )

    monkeypatch.setattr(settings_router, "get_token_from_source_connections", lambda org: "primary-token")

    async def fake_fetch_rate_limit(token: str):
        assert token == "primary-token"
        return {
            "limit": 5000,
            "remaining": 4991,
            "reset": 1710000000,
            "used": 9,
        }

    monkeypatch.setattr(settings_router, "fetch_rate_limit", fake_fetch_rate_limit)

    response = client.get("/settings/api/orgs/Example-Org/rate-limit")

    assert response.status_code == 200
    assert response.json() == {
        "limit": 5000,
        "remaining": 4991,
        "reset_at": "2024-03-09T16:00:00+00:00",
        "used": 9,
    }


def test_get_settings_redacts_secret_ai_api_key(monkeypatch):
    import src.settings.router as settings_api

    monkeypatch.setattr(
        settings_api,
        "read_app_config",
        lambda: {
            "github": {"orgs": [{"name": "Example-Org", "token": "ghp_token"}]},
            "dashboard": {"username": "admin", "password": "pw", "sessionSecret": "session"},
            "tools": {
                "codeScanning": {
                    "enabled": True,
                    "autoRefreshSeconds": "120",
                    "source": "github-code-scanning",
                },
                "secrets": {
                    "enabled": True,
                    "scanConcurrency": "4",
                    "dockerImage": "github-secrets",
                    "aiReviewEnabled": True,
                    "aiApiKey": "sk-real-secret",
                },
                "iacSecurity": {"enabled": False},
            },
        },
    )

    safe = settings_api._safe_config(settings_api.read_app_config())

    assert safe["tools"]["secrets"]["aiApiKey"] == "[redacted]"
    assert safe["dashboard"]["password"] == ""
    assert safe["dashboard"]["sessionSecret"] == ""


@pytest.mark.asyncio
async def test_save_secret_settings_preserves_redacted_ai_api_key(monkeypatch):
    import src.settings.router as settings_api
    from src.settings.schemas import ToolSettingsRequest

    config_value = {
        "github": {"orgs": [{"name": "Example-Org", "token": "ghp_token"}]},
        "dashboard": {"username": "admin", "password": "", "sessionSecret": "session"},
        "tools": {
            "codeScanning": {
                "enabled": True,
                    "autoRefreshSeconds": "120",
                "source": "github-code-scanning",
            },
            "secrets": {
                "enabled": False,
                    "scanConcurrency": "4",
                "dockerImage": "github-secrets",
                "aiReviewEnabled": True,
                "aiApiKey": "sk-existing-secret",
            },
            "iacSecurity": {"enabled": False},
        },
    }
    written: dict[str, object] = {}

    monkeypatch.setattr(settings_api, "read_app_config", lambda: config_value)
    monkeypatch.setattr(settings_api, "write_app_config", lambda config, event_type: written.update(config=config, event_type=event_type))
    monkeypatch.setattr(settings_api, "sync_runtime_env_from_config", lambda config: None)

    body = ToolSettingsRequest(
        enabled=False,
        settings={
            "scanConcurrency": "4",
            "dockerImage": "github-secrets",
            "aiReviewEnabled": "true",
            "aiApiKey": "[redacted]",
            "aiBaseUrl": "https://api.openai.com/v1",
            "aiModelName": "gpt-4o-mini",
        },
    )

    from unittest.mock import MagicMock
    mock_request = MagicMock()
    mock_request.state.user_role = "owner"
    mock_request.state.user_role_id = None

    await settings_api.save_tool_settings(mock_request, "secrets", body)

    saved = written["config"]
    assert saved["tools"]["secrets"]["aiReviewEnabled"] is True
    assert saved["tools"]["secrets"]["aiApiKey"] == "sk-existing-secret"


def test_get_rate_limit_missing_saved_pat_returns_404(client, isolated_config):
    config.write_app_config(
        {
            "github": {"orgs": []},
            "dashboard": {
                "username": "ops-admin",
                "password": "current-password",
                "sessionSecret": "existing-session-secret",
            },
            "tools": {
                "dependencies": {
                    "enabled": True,
                },
                "codeScanning": {
                    "enabled": True,
                    "autoRefreshSeconds": "120",
                    "source": "github-code-scanning",
                },
                "secrets": {
                    "enabled": True,
                    "scanConcurrency": "4",
                },
            },
        }
    )

    response = client.get("/settings/api/orgs/no-such-org/rate-limit")

    assert response.status_code == 404
    assert response.json() == {"detail": "No PAT saved for no-such-org. Enter a token first."}


def test_get_secrets_prerequisites_returns_no_runner_when_offline(client, isolated_config, monkeypatch):
    """Prerequisites fail when no runner is online."""
    response = client.get("/settings/api/tools/secrets/prerequisites")

    assert response.status_code == 200
    payload = response.json()
    assert payload["docker_image_present"] is False
    assert payload["scanner_status"] == "no_runner"
    assert payload["error"] is not None


def test_get_roles_returns_seeded_roles(client, monkeypatch):
    secret = "a" * 64
    monkeypatch.setenv("JWT_SHARED_SECRET", secret)

    response = client.get("/settings/api/roles", headers=_auth_headers("admin", secret))
    assert response.status_code == 200
    payload = response.json()
    assert any(role["name"] == "Owner" for role in payload["roles"])

def test_post_role_creates_custom_role(client, monkeypatch):
    secret = "a" * 64
    monkeypatch.setenv("JWT_SHARED_SECRET", secret)

    response = client.post(
        "/settings/api/roles",
        headers=_auth_headers("admin", secret),
        json={
            "name": "Results Viewer",
            "description": "Read-only results role.",
            "permissions": ["view_dashboards", "view_findings"],
        },
    )
    assert response.status_code == 200
    assert response.json()["role"]["name"] == "Results Viewer"

def test_require_permission_uses_assigned_role_permissions(client, isolated_config, monkeypatch):
    from src.settings import roles_store

    secret = "b" * 64
    monkeypatch.setenv("JWT_SHARED_SECRET", secret)
    monkeypatch.setenv("FASTAPI_ENV", "production")

    # Viewer should not be able to get roles
    response = client.get("/settings/api/roles", headers=_auth_headers("viewer", secret))
    assert response.status_code == 403

    # Admin should be able to get roles
    response = client.get("/settings/api/roles", headers=_auth_headers("admin", secret))
    assert response.status_code == 200

    # Custom role via roleId
    custom_role = roles_store.create_role({
        "name": "Custom",
        "slug": "custom",
        "description": "",
        "permissions": ["view_roles"]
    })

    # Using the custom roleId should allow access even if 'role' is viewer
    response = client.get("/settings/api/roles", headers=_auth_headers("viewer", secret, role_id=custom_role["id"]))
    assert response.status_code == 200
