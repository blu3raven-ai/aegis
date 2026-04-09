from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from src.shared.paths import repo_root

ENV_PATH = repo_root() / ".env.local"


def parse_org_list(raw: str) -> list[str]:
    by_key: dict[str, str] = {}
    for value in raw.split(","):
        org = value.strip()
        if not org:
            continue
        by_key.setdefault(org.lower(), org)
    return list(by_key.values())


def _unquote_env_value(value: str) -> str:
    trimmed = value.strip()
    if len(trimmed) >= 2 and trimmed[0] == trimmed[-1] and trimmed[0] in {"'", '"'}:
        return trimmed[1:-1]
    return trimmed


def read_env_file(path: Path | None = None) -> dict[str, str]:
    path = path or ENV_PATH
    out: dict[str, str] = {}
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except FileNotFoundError:
        return out

    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith("export "):
            stripped = stripped[len("export ") :].strip()
        key, sep, value = stripped.partition("=")
        if not sep:
            continue
        key = key.strip()
        if key:
            out[key] = _unquote_env_value(value)
    return out


def env_source() -> dict[str, str]:
    # Keep parity with the current Next-side semantics: process env values are
    # visible, and .env.local fills in machine-local defaults from disk.
    return {**read_env_file(), **os.environ}


def _to_bool(value: str | None, fallback: bool) -> bool:
    if value is None:
        return fallback
    return value.lower() != "false"


def app_config_from_env_map(env: dict[str, str]) -> dict[str, Any]:
    return {
        "dashboard": {
            "username": env.get("ADMIN_USERNAME") or "admin",
            "email": env.get("ADMIN_EMAIL") or "",
            "password": env.get("ADMIN_PASSWORD") or "",
            "sessionSecret": env.get("SESSION_SECRET") or "",
        },
        "authSecurity": {
            "requireMfaManualUsers": _to_bool(env.get("AUTH_SECURITY_REQUIRE_MFA_MANUAL"), False),
            "requireMfaAdmins": _to_bool(env.get("AUTH_SECURITY_REQUIRE_MFA_ADMINS"), False),
            "trustedSessionDurationDays": int(env.get("AUTH_SECURITY_TRUSTED_SESSION_DURATION") or "30"),
            "recoveryCodePolicy": env.get("AUTH_SECURITY_RECOVERY_CODE_POLICY") or "mandatory",
        },
        "tools": {
            "dependencies": {
                "enabled": _to_bool(env.get("SCA_ENABLED"), False),
                "autoRerunEnabled": _to_bool(env.get("SCA_AUTO_RERUN_ENABLED"), False),
                "rerunScheduleType": env.get("SCA_RERUN_SCHEDULE_TYPE") or "simple",
                "rerunScheduleValue": env.get("SCA_RERUN_SCHEDULE_VALUE") or "02:00",
                "scanConcurrency": env.get("SCA_SCAN_CONCURRENCY") or "4",
                "dockerImage": env.get("SCA_SCANNER_IMAGE") or "aegis/scanner-dependencies:latest",
                "nvdEnabled": env.get("SCA_NVD_ENABLED", "").lower() != "false",
                "nvdApiKey": env.get("SCA_NVD_API_KEY") or "",
                "ghsaEnabled": env.get("SCA_GHSA_ENABLED", "").lower() == "true",
                "ghsaApiKey": env.get("SCA_GHSA_API_KEY") or "",
                "retentionDays": int(env.get("SCA_RETENTION_DAYS") or "7"),
            },
            "containerScanning": {
                "enabled": _to_bool(env.get("CONTAINER_SCANNING_ENABLED"), False),
                "autoRerunEnabled": _to_bool(env.get("CONTAINER_SCANNING_AUTO_RERUN_ENABLED"), False),
                "rerunScheduleType": env.get("CONTAINER_SCANNING_RERUN_SCHEDULE_TYPE") or "simple",
                "rerunScheduleValue": env.get("CONTAINER_SCANNING_RERUN_SCHEDULE_VALUE") or "02:00",
                "scanConcurrency": env.get("CONTAINER_SCAN_CONCURRENCY") or "4",
                "dockerImage": env.get("CONTAINER_SCANNER_IMAGE") or "aegis/scanner-container:latest",
                "nvdEnabled": env.get("CONTAINER_SCANNING_NVD_ENABLED", "true").lower() != "false",
                "nvdApiKey": env.get("CONTAINER_SCANNING_NVD_API_KEY") or "",
                "ghsaEnabled": env.get("CONTAINER_SCANNING_GHSA_ENABLED", "false").lower() == "true",
                "ghsaApiKey": env.get("CONTAINER_SCANNING_GHSA_API_KEY") or "",
                "argusEnabled": env.get("CONTAINER_SCANNING_ARGUS_ENABLED", "false").lower() == "true",
                "argusApiKey": env.get("CONTAINER_SCANNING_ARGUS_API_KEY") or "",
                "retentionDays": int(env.get("CONTAINER_SCANNING_RETENTION_DAYS") or "7"),
            },
            "codeScanning": {
                "enabled": _to_bool(env.get("SAST_ENABLED"), False),
                "dockerImage": env.get("SAST_DOCKER_IMAGE") or "aegis/scanner-code-scanning:latest",
                "scanConcurrency": env.get("SAST_SCAN_CONCURRENCY") or "4",
                "rulesets": (env.get("SAST_RULESETS") or "p/owasp-top-ten,p/cwe-top-25").split(","),
                "aiReviewEnabled": _to_bool(env.get("SAST_AI_REVIEW_ENABLED"), False),
                "aiApiKey": env.get("SAST_AI_API_KEY") or "",
                "aiBaseUrl": env.get("SAST_AI_BASE_URL") or "https://api.openai.com/v1",
                "aiModelName": env.get("SAST_AI_MODEL") or "gpt-4o-mini",
                "aiAutoClassifyOnScan": _to_bool(env.get("SAST_AI_AUTO_CLASSIFY_ON_SCAN"), False),
                "autoRerunEnabled": _to_bool(env.get("SAST_AUTO_RERUN_ENABLED"), False),
                "rerunScheduleType": env.get("SAST_RERUN_SCHEDULE_TYPE") or "simple",
                "rerunScheduleValue": env.get("SAST_RERUN_SCHEDULE_VALUE") or "02:00",
                "retentionDays": int(env.get("SAST_RETENTION_DAYS") or "7"),
            },
            "secrets": {
                "enabled": _to_bool(env.get("SECRETS_ENABLED"), False),
                "scanConcurrency": env.get("SECRET_SCANNER_CONCURRENCY") or env.get("SECRETS_SCAN_CONCURRENCY") or "4",
                "dockerImage": env.get("SECRET_SCANNER_IMAGE") or "aegis/scanner-secrets:latest",
                "scanDepth": env.get("SECRETS_SCAN_DEPTH") or "light",
                "scanHistoryWindow": env.get("SECRETS_SCAN_HISTORY_WINDOW") or "all",
                "aiReviewEnabled": _to_bool(env.get("SECRETS_AI_REVIEW_ENABLED"), False),
                "aiApiKey": env.get("SECRETS_AI_API_KEY") or "",
                "autoRerunEnabled": _to_bool(env.get("SECRETS_AUTO_RERUN_ENABLED"), False),
                "rerunScheduleType": env.get("SECRETS_RERUN_SCHEDULE_TYPE") or "simple",
                "rerunScheduleValue": env.get("SECRETS_RERUN_SCHEDULE_VALUE") or "02:00",
                "retentionDays": int(env.get("SECRETS_RETENTION_DAYS") or "7"),
            },
            "iacSecurity": {
                "enabled": _to_bool(env.get("IAC_SECURITY_ENABLED"), False),
            },
        },
    }


def _normalize_config(value: dict[str, Any] | None, fallback: dict[str, Any]) -> dict[str, Any]:
    value = value if isinstance(value, dict) else {}

    dashboard = value.get("dashboard") if isinstance(value.get("dashboard"), dict) else {}
    auth_security = value.get("authSecurity") if isinstance(value.get("authSecurity"), dict) else {}
    tools = value.get("tools") if isinstance(value.get("tools"), dict) else {}
    dependencies = tools.get("dependencies") if isinstance(tools.get("dependencies"), dict) else {}
    container_scanning_cfg = tools.get("containerScanning") if isinstance(tools.get("containerScanning"), dict) else {}
    code_scanning = tools.get("codeScanning") if isinstance(tools.get("codeScanning"), dict) else {}
    secrets = tools.get("secrets") if isinstance(tools.get("secrets"), dict) else {}
    iac_security = tools.get("iacSecurity") if isinstance(tools.get("iacSecurity"), dict) else {}

    return {
        "dashboard": {
            "username": dashboard.get("username", fallback["dashboard"]["username"]),
            "email": dashboard.get("email", fallback["dashboard"]["email"]),
            "password": dashboard.get("password", fallback["dashboard"]["password"]),
            "sessionSecret": dashboard.get("sessionSecret", fallback["dashboard"]["sessionSecret"]),
        },
        "authSecurity": {
            "requireMfaManualUsers": auth_security.get(
                "requireMfaManualUsers", fallback["authSecurity"]["requireMfaManualUsers"]
            ),
            "requireMfaAdmins": auth_security.get(
                "requireMfaAdmins", fallback["authSecurity"]["requireMfaAdmins"]
            ),
            "trustedSessionDurationDays": auth_security.get(
                "trustedSessionDurationDays", fallback["authSecurity"]["trustedSessionDurationDays"]
            ),
            "recoveryCodePolicy": auth_security.get(
                "recoveryCodePolicy", fallback["authSecurity"]["recoveryCodePolicy"]
            ),
        },
        "tools": {
            "dependencies": {
                "enabled": dependencies.get("enabled", fallback["tools"]["dependencies"]["enabled"]),
                "autoRerunEnabled": dependencies.get("autoRerunEnabled", fallback["tools"]["dependencies"]["autoRerunEnabled"]),
                "rerunScheduleType": dependencies.get("rerunScheduleType", fallback["tools"]["dependencies"]["rerunScheduleType"]),
                "rerunScheduleValue": dependencies.get("rerunScheduleValue", fallback["tools"]["dependencies"]["rerunScheduleValue"]),
                "scanConcurrency": dependencies.get("scanConcurrency", fallback["tools"]["dependencies"]["scanConcurrency"]),
                "dockerImage": dependencies.get("dockerImage", fallback["tools"]["dependencies"]["dockerImage"]),
                "nvdEnabled": dependencies.get("nvdEnabled", fallback["tools"]["dependencies"]["nvdEnabled"]),
                "nvdApiKey": dependencies.get("nvdApiKey", fallback["tools"]["dependencies"]["nvdApiKey"]),
                "ghsaEnabled": dependencies.get("ghsaEnabled", fallback["tools"]["dependencies"]["ghsaEnabled"]),
                "ghsaApiKey": dependencies.get("ghsaApiKey", fallback["tools"]["dependencies"]["ghsaApiKey"]),
                "retentionDays": dependencies.get("retentionDays", fallback["tools"]["dependencies"]["retentionDays"]),
            },
            "containerScanning": {
                "enabled": container_scanning_cfg.get("enabled", fallback["tools"]["containerScanning"]["enabled"]),
                "autoRerunEnabled": container_scanning_cfg.get("autoRerunEnabled", fallback["tools"]["containerScanning"]["autoRerunEnabled"]),
                "rerunScheduleType": container_scanning_cfg.get("rerunScheduleType", fallback["tools"]["containerScanning"]["rerunScheduleType"]),
                "rerunScheduleValue": container_scanning_cfg.get("rerunScheduleValue", fallback["tools"]["containerScanning"]["rerunScheduleValue"]),
                "scanConcurrency": container_scanning_cfg.get("scanConcurrency", fallback["tools"]["containerScanning"]["scanConcurrency"]),
                "dockerImage": container_scanning_cfg.get("dockerImage", fallback["tools"]["containerScanning"]["dockerImage"]),
                "nvdEnabled": container_scanning_cfg.get("nvdEnabled", fallback["tools"]["containerScanning"]["nvdEnabled"]),
                "nvdApiKey": container_scanning_cfg.get("nvdApiKey", fallback["tools"]["containerScanning"]["nvdApiKey"]),
                "ghsaEnabled": container_scanning_cfg.get("ghsaEnabled", fallback["tools"]["containerScanning"]["ghsaEnabled"]),
                "ghsaApiKey": container_scanning_cfg.get("ghsaApiKey", fallback["tools"]["containerScanning"]["ghsaApiKey"]),
                "argusEnabled": container_scanning_cfg.get("argusEnabled", fallback["tools"]["containerScanning"]["argusEnabled"]),
                "argusApiKey": container_scanning_cfg.get("argusApiKey", fallback["tools"]["containerScanning"]["argusApiKey"]),
                "retentionDays": container_scanning_cfg.get("retentionDays", fallback["tools"]["containerScanning"]["retentionDays"]),
            },
            "codeScanning": {
                "enabled": code_scanning.get("enabled", fallback["tools"]["codeScanning"]["enabled"]),
                "dockerImage": code_scanning.get("dockerImage", fallback["tools"]["codeScanning"]["dockerImage"]),
                "scanConcurrency": code_scanning.get("scanConcurrency", fallback["tools"]["codeScanning"]["scanConcurrency"]),
                "rulesets": code_scanning.get("rulesets", fallback["tools"]["codeScanning"]["rulesets"]),
                "aiReviewEnabled": code_scanning.get("aiReviewEnabled", fallback["tools"]["codeScanning"]["aiReviewEnabled"]),
                "aiApiKey": code_scanning.get("aiApiKey", fallback["tools"]["codeScanning"]["aiApiKey"]),
                "aiBaseUrl": code_scanning.get("aiBaseUrl", fallback["tools"]["codeScanning"]["aiBaseUrl"]),
                "aiModelName": code_scanning.get("aiModelName", fallback["tools"]["codeScanning"]["aiModelName"]),
                "aiAutoClassifyOnScan": code_scanning.get("aiAutoClassifyOnScan", fallback["tools"]["codeScanning"]["aiAutoClassifyOnScan"]),
                "autoRerunEnabled": code_scanning.get("autoRerunEnabled", fallback["tools"]["codeScanning"]["autoRerunEnabled"]),
                "rerunScheduleType": code_scanning.get("rerunScheduleType", fallback["tools"]["codeScanning"]["rerunScheduleType"]),
                "rerunScheduleValue": code_scanning.get("rerunScheduleValue", fallback["tools"]["codeScanning"]["rerunScheduleValue"]),
                "retentionDays": code_scanning.get("retentionDays", fallback["tools"]["codeScanning"]["retentionDays"]),
            },
            "secrets": {
                "enabled": secrets.get("enabled", fallback["tools"]["secrets"]["enabled"]),
                "scanConcurrency": secrets.get(
                    "scanConcurrency", fallback["tools"]["secrets"]["scanConcurrency"]
                ),
                "dockerImage": secrets.get("dockerImage", fallback["tools"]["secrets"]["dockerImage"]),
                "scanDepth": secrets.get("scanDepth", fallback["tools"]["secrets"]["scanDepth"]),
                "scanHistoryWindow": secrets.get("scanHistoryWindow", fallback["tools"]["secrets"]["scanHistoryWindow"]),
                "aiReviewEnabled": secrets.get("aiReviewEnabled", fallback["tools"]["secrets"]["aiReviewEnabled"]),
                "aiApiKey": secrets.get("aiApiKey", fallback["tools"]["secrets"]["aiApiKey"]),
                "autoRerunEnabled": secrets.get(
                    "autoRerunEnabled", fallback["tools"]["secrets"]["autoRerunEnabled"]
                ),
                "rerunScheduleType": secrets.get(
                    "rerunScheduleType", fallback["tools"]["secrets"]["rerunScheduleType"]
                ),
                "rerunScheduleValue": secrets.get(
                    "rerunScheduleValue", fallback["tools"]["secrets"]["rerunScheduleValue"]
                ),
                "retentionDays": secrets.get("retentionDays", fallback["tools"]["secrets"]["retentionDays"]),
            },
            "iacSecurity": {
                "enabled": iac_security.get("enabled", fallback["tools"]["iacSecurity"]["enabled"]),
            },
        },
        # Runner config
        "runners": {
            "mode": (value.get("runners") or {}).get("mode", "local"),
        },
    }


def read_app_config() -> dict[str, Any]:
    from src.db.helpers import run_db
    from src.db.models import AppConfig

    async def _query(session):
        row = await session.get(AppConfig, 1)
        return row.config if row and isinstance(row.config, dict) else None

    fallback = app_config_from_env_map(env_source())
    try:
        db_config = run_db(_query)
    except Exception:
        db_config = None
    return _normalize_config(db_config, fallback)


def app_config_to_env(config: dict[str, Any]) -> dict[str, str]:
    env: dict[str, str] = {}

    dashboard = config.get("dashboard") if isinstance(config.get("dashboard"), dict) else {}
    env["ADMIN_USERNAME"] = str(dashboard.get("username") or "admin")
    env["ADMIN_PASSWORD"] = str(dashboard.get("password") or "")
    env["SESSION_SECRET"] = str(dashboard.get("sessionSecret") or "")

    auth_security = config.get("authSecurity") if isinstance(config.get("authSecurity"), dict) else {}
    env["AUTH_SECURITY_REQUIRE_MFA_MANUAL"] = "true" if auth_security.get("requireMfaManualUsers", False) else "false"
    env["AUTH_SECURITY_REQUIRE_MFA_ADMINS"] = "true" if auth_security.get("requireMfaAdmins", False) else "false"
    env["AUTH_SECURITY_TRUSTED_SESSION_DURATION"] = str(auth_security.get("trustedSessionDurationDays") or "30")
    env["AUTH_SECURITY_RECOVERY_CODE_POLICY"] = str(auth_security.get("recoveryCodePolicy") or "mandatory")

    tools = config.get("tools") if isinstance(config.get("tools"), dict) else {}

    dependencies = tools.get("dependencies") if isinstance(tools.get("dependencies"), dict) else {}
    env["SCA_ENABLED"] = "true" if dependencies.get("enabled", False) else "false"
    env["SCA_AUTO_RERUN_ENABLED"] = "true" if dependencies.get("autoRerunEnabled", False) else "false"
    env["SCA_RERUN_SCHEDULE_TYPE"] = str(dependencies.get("rerunScheduleType") or "simple")
    env["SCA_RERUN_SCHEDULE_VALUE"] = str(dependencies.get("rerunScheduleValue") or "02:00")
    env["SCA_SCAN_CONCURRENCY"] = str(dependencies.get("scanConcurrency") or "4")
    env["SCA_SCANNER_IMAGE"] = str(dependencies.get("dockerImage") or "aegis/scanner-dependencies:latest")
    env["SCA_RETENTION_DAYS"] = str(dependencies.get("retentionDays") or "7")

    container_scanning_cfg = tools.get("containerScanning") if isinstance(tools.get("containerScanning"), dict) else {}
    env["CONTAINER_SCANNING_ENABLED"] = "true" if container_scanning_cfg.get("enabled", False) else "false"
    env["CONTAINER_SCANNING_AUTO_RERUN_ENABLED"] = "true" if container_scanning_cfg.get("autoRerunEnabled", False) else "false"
    env["CONTAINER_SCANNING_RERUN_SCHEDULE_TYPE"] = str(container_scanning_cfg.get("rerunScheduleType") or "simple")
    env["CONTAINER_SCANNING_RERUN_SCHEDULE_VALUE"] = str(container_scanning_cfg.get("rerunScheduleValue") or "02:00")
    env["CONTAINER_SCAN_CONCURRENCY"] = str(container_scanning_cfg.get("scanConcurrency") or "4")
    env["CONTAINER_SCANNER_IMAGE"] = str(container_scanning_cfg.get("dockerImage") or "aegis/scanner-container:latest")
    env["CONTAINER_SCANNING_RETENTION_DAYS"] = str(container_scanning_cfg.get("retentionDays") or "7")

    code_scanning = tools.get("codeScanning") if isinstance(tools.get("codeScanning"), dict) else {}
    env["SAST_ENABLED"] = "true" if code_scanning.get("enabled", False) else "false"
    env["SAST_DOCKER_IMAGE"] = str(code_scanning.get("dockerImage") or "aegis/scanner-code-scanning:latest")
    env["SAST_SCAN_CONCURRENCY"] = str(code_scanning.get("scanConcurrency") or "4")
    rulesets = code_scanning.get("rulesets") or ["p/owasp-top-ten", "p/cwe-top-25"]
    env["SAST_RULESETS"] = ",".join(rulesets) if isinstance(rulesets, list) else str(rulesets)
    env["SAST_AI_REVIEW_ENABLED"] = "true" if code_scanning.get("aiReviewEnabled", False) else "false"
    env["SAST_AI_API_KEY"] = str(code_scanning.get("aiApiKey") or "")
    env["SAST_AI_BASE_URL"] = str(code_scanning.get("aiBaseUrl") or "https://api.openai.com/v1")
    env["SAST_AI_MODEL"] = str(code_scanning.get("aiModelName") or "gpt-4o-mini")
    env["SAST_AI_AUTO_CLASSIFY_ON_SCAN"] = "true" if code_scanning.get("aiAutoClassifyOnScan", False) else "false"
    env["SAST_AUTO_RERUN_ENABLED"] = "true" if code_scanning.get("autoRerunEnabled", False) else "false"
    env["SAST_RERUN_SCHEDULE_TYPE"] = str(code_scanning.get("rerunScheduleType") or "simple")
    env["SAST_RERUN_SCHEDULE_VALUE"] = str(code_scanning.get("rerunScheduleValue") or "02:00")
    env["SAST_RETENTION_DAYS"] = str(code_scanning.get("retentionDays") or "7")

    secrets = tools.get("secrets") if isinstance(tools.get("secrets"), dict) else {}
    env["SECRETS_ENABLED"] = "true" if secrets.get("enabled", True) else "false"
    scan_concurrency = str(secrets.get("scanConcurrency") or "4")
    env["SECRET_SCANNER_CONCURRENCY"] = scan_concurrency
    env["SECRETS_SCAN_CONCURRENCY"] = scan_concurrency
    env["SECRET_SCANNER_IMAGE"] = str(secrets.get("dockerImage") or "aegis/scanner-secrets:latest")
    env["SECRETS_SCAN_DEPTH"] = str(secrets.get("scanDepth") or "light")
    env["SECRETS_AI_REVIEW_ENABLED"] = "true" if secrets.get("aiReviewEnabled", False) else "false"
    env["SECRETS_AI_API_KEY"] = str(secrets.get("aiApiKey") or "")
    env["SECRETS_AUTO_RERUN_ENABLED"] = "true" if secrets.get("autoRerunEnabled", False) else "false"
    env["SECRETS_RERUN_SCHEDULE_TYPE"] = str(secrets.get("rerunScheduleType") or "simple")
    env["SECRETS_RERUN_SCHEDULE_VALUE"] = str(secrets.get("rerunScheduleValue") or "02:00")
    env["SECRETS_RETENTION_DAYS"] = str(secrets.get("retentionDays") or "7")

    iac_security = tools.get("iacSecurity") if isinstance(tools.get("iacSecurity"), dict) else {}
    env["IAC_SECURITY_ENABLED"] = "true" if iac_security.get("enabled", False) else "false"

    return env


def _redact_config(config: dict[str, Any]) -> dict[str, Any]:
    # Shallow copy for redacting to avoid side effects on original config
    result = {**config}
    
    dashboard = result.get("dashboard")
    if isinstance(dashboard, dict):
        dashboard_copy = {**dashboard}
        if dashboard_copy.get("password"):
            dashboard_copy["password"] = "[redacted]"
        if dashboard_copy.get("sessionSecret"):
            dashboard_copy["sessionSecret"] = "[redacted]"
        result["dashboard"] = dashboard_copy
        
    result["authSecurity"] = {**result.get("authSecurity", {})}

    tools = result.get("tools")
    if isinstance(tools, dict):
        tools_copy = {**tools}

        # Keys that must be redacted per tool section
        _SENSITIVE_KEYS = {"aiApiKey", "nvdApiKey", "ghsaApiKey", "argusApiKey", "argusEndpoint"}

        for tool_name in ("codeScanning", "dependencies", "containerScanning", "secrets"):
            tool_cfg = tools_copy.get(tool_name)
            if not isinstance(tool_cfg, dict):
                continue
            redacted = {k: ("[redacted]" if k in _SENSITIVE_KEYS and v else v) for k, v in tool_cfg.items()}
            if redacted != tool_cfg:
                tools_copy[tool_name] = redacted

        result["tools"] = tools_copy

    return result


def write_app_config(config: dict[str, Any], event_type: str = "settings.updated") -> None:
    from src.db.helpers import run_db
    from src.db.models import AppConfig

    async def _query(session):
        row = await session.get(AppConfig, 1)
        if row:
            row.config = config
            row.updated_at = datetime.now(timezone.utc)
        else:
            session.add(AppConfig(id=1, config=config, updated_at=datetime.now(timezone.utc)))

    run_db(_query)

    # Log config change to audit trail
    from src.settings.audit import record_event
    record_event(
        action=event_type,
        metadata=_redact_config(config),
    )


def sync_runtime_env_from_config(
    config: dict[str, Any],
    removed_keys: list[str] | None = None,
) -> None:
    for key in removed_keys or []:
        os.environ.pop(key, None)
    for key, value in app_config_to_env(config).items():
        os.environ[key] = value


def get_app_config_env_value(key: str) -> str:
    config_value = app_config_to_env(read_app_config()).get(key)
    if config_value:
        return config_value
    return env_source().get(key, "")


def _read_source_connections() -> list[dict[str, Any]]:
    from src.settings.sources_store import list_connections_with_secrets
    try:
        return list_connections_with_secrets()
    except Exception:
        return []


def get_orgs_from_source_connections() -> list[str]:
    by_key: dict[str, str] = {}
    for conn in _read_source_connections():
        auth = conn.get("auth") if isinstance(conn.get("auth"), dict) else {}
        org = (auth.get("orgOrOwner") or "").strip()
        if not org:
            continue
        by_key.setdefault(org.lower(), org)
    return list(by_key.values())


def get_token_from_source_connections(org: str) -> str:
    key = org.lower()
    for conn in _read_source_connections():
        if conn.get("status") != "connected":
            continue
        auth = conn.get("auth") if isinstance(conn.get("auth"), dict) else {}
        conn_org = (auth.get("orgOrOwner") or "").strip()
        if conn_org and conn_org.lower() == key and auth.get("token"):
            return str(auth["token"])
    return ""


def get_github_token_for_org(org: str) -> str:
    return get_token_from_source_connections(org)


@dataclass
class ScanSource:
    """A single source connection with resolved scan targets (shared by SCA & Secrets)."""
    connection_id: str
    category: str          # "code-repositories" or "container-images"
    source_type: str       # "github", "gitlab", "ghcr", "docker-hub"
    org: str
    token: str
    repo_urls: list[str]         # clone URLs (for code-repositories)
    container_images: list[str]  # image refs (for container-images)
    registry_token: str          # auth token for container registries
    registry_username: str       # username for container registries (optional)


def get_scan_sources_for_org(org: str) -> list[ScanSource]:
    """Return resolved SCA source connections for an org, one per connection.

    Each ScanSource has either repo_urls or container_images populated,
    allowing the scanner to iterate source-by-source.
    """
    key = org.lower()
    sources: list[ScanSource] = []
    for conn in _read_source_connections():
        category = conn.get("category", "")
        if category not in ("code-repositories", "container-images"):
            continue
        if conn.get("status") != "connected":
            continue
        auth = conn.get("auth") if isinstance(conn.get("auth"), dict) else {}
        conn_org = (auth.get("orgOrOwner") or "").strip()
        if not conn_org or conn_org.lower() != key:
            continue
        token = str(auth.get("token") or "")
        if not token:
            continue

        source_type = conn.get("sourceType", "")
        scan_scope = conn.get("scanScope", "all")
        discovered = conn.get("discoveredItems") or []
        excluded = set(conn.get("excludedItems") or []) if scan_scope == "all-except-excluded" else set()

        repo_urls: list[str] = []
        container_images: list[str] = []
        registry_token = ""
        instance_url = (auth.get("instanceUrl") or "").rstrip("/")

        for item in discovered:
            if not isinstance(item, str) or not item.strip() or item in excluded:
                continue
            name = item.strip()

            if category == "code-repositories":
                repo_path = name if "/" in name else f"{conn_org}/{name}"
                if source_type == "github":
                    repo_urls.append(f"https://github.com/{repo_path}.git")
                elif source_type == "gitlab":
                    base = instance_url or "https://gitlab.com"
                    repo_urls.append(f"{base}/{repo_path}.git")
                elif source_type == "bitbucket":
                    repo_urls.append(f"https://bitbucket.org/{repo_path}.git")
                elif source_type == "gitea":
                    base = instance_url or "https://gitea.com"
                    repo_urls.append(f"{base}/{repo_path}.git")

            elif category == "container-images":
                name_without_tag = name.split(":")[0]
                if "." not in name_without_tag.split("/")[0]:
                    if source_type == "ghcr":
                        name = f"ghcr.io/{conn_org}/{name}"
                    elif source_type == "docker-hub":
                        name = f"{conn_org}/{name}" if "/" not in name_without_tag else name
                    elif source_type == "ecr":
                        registry_url = (instance_url or "").rstrip("/")
                        name = f"{registry_url}/{name}" if registry_url else name
                    elif source_type == "acr":
                        registry_url = (instance_url or "").rstrip("/")
                        name = f"{registry_url}/{name}" if registry_url else name
                    elif source_type == "gcr":
                        registry_url = (instance_url or "gcr.io").rstrip("/")
                        name = f"{registry_url}/{conn_org}/{name}"
                    elif source_type == "gitlab-registry":
                        base = instance_url or "registry.gitlab.com"
                        name = f"{base}/{conn_org}/{name}"
                container_images.append(name)
                registry_token = token

        if repo_urls or container_images:
            sources.append(ScanSource(
                connection_id=conn.get("id", ""),
                category=category,
                source_type=source_type,
                org=conn_org,
                token=token,
                repo_urls=repo_urls,
                container_images=container_images,
                registry_token=registry_token if category == "container-images" else "",
                registry_username=auth.get("username", "") if category == "container-images" else "",
            ))
    return sources


def build_source_repo_list(sources: list[ScanSource]) -> list[dict[str, Any]]:
    """Build a deduplicated repo/image list from scan sources.

    Extracts full_name and short name from repo clone URLs and container image
    refs.  Used by both the scanner (post-scan analytics) and the router
    (dashboard snapshot).
    """
    repos: dict[str, dict[str, Any]] = {}
    for source in sources:
        for url in source.repo_urls:
            repo_path = url.rstrip("/").removesuffix(".git").split("/")[-2:]
            full_name = "/".join(repo_path)
            if full_name not in repos:
                repos[full_name] = {"full_name": full_name, "name": repo_path[-1]}
        for img in source.container_images:
            if img not in repos:
                repos[img] = {"full_name": img, "name": img.split("/")[-1].split(":")[0]}
    return list(repos.values())


def org_has_source_connections(org: str, categories: list[str] | None = None) -> bool:
    """Check if an org has at least one connected source connection with a token.

    If categories is provided, only connections matching those categories are considered.
    """
    key = org.lower()
    for conn in _read_source_connections():
        if conn.get("status") != "connected":
            continue
        if categories and conn.get("category") not in categories:
            continue
        auth = conn.get("auth") if isinstance(conn.get("auth"), dict) else {}
        conn_org = (auth.get("orgOrOwner") or "").strip()
        if conn_org and conn_org.lower() == key and auth.get("token"):
            return True
    return False


def get_secret_scanner_config() -> dict[str, str]:
    config = read_app_config()
    secrets_tool = (config.get("tools") or {}).get("secrets") or {}
    image = str(secrets_tool.get("dockerImage") or "").strip() or env_source().get("SECRET_SCANNER_IMAGE") or "aegis/scanner-secrets:latest"
    concurrency = str(secrets_tool.get("scanConcurrency") or "").strip() or get_app_config_env_value("SECRET_SCANNER_CONCURRENCY") or get_app_config_env_value("SECRETS_SCAN_CONCURRENCY") or "4"
    scan_depth = str(secrets_tool.get("scanDepth") or "").strip().lower() or "light"
    if scan_depth not in ("light", "deep", "ai_enhanced"):
        scan_depth = "light"
    history_window = str(secrets_tool.get("scanHistoryWindow") or "all").strip()
    _window_days = {"30d": 30, "90d": 90, "180d": 180, "365d": 365}
    scan_start_date = ""
    if history_window in _window_days:
        scan_start_date = (date.today() - timedelta(days=_window_days[history_window])).isoformat()
    return {
        "image": image,
        "concurrency": concurrency,
        "scanStartDate": scan_start_date,
        "scanDepth": scan_depth,
    }


def get_dependencies_scanner_config() -> dict[str, str]:
    config = read_app_config()
    deps_tool = (config.get("tools") or {}).get("dependencies") or {}
    image = str(deps_tool.get("dockerImage") or "").strip() or env_source().get("SCA_SCANNER_IMAGE") or "aegis/scanner-dependencies:latest"
    concurrency = str(deps_tool.get("scanConcurrency") or "").strip() or get_app_config_env_value("SCA_SCAN_CONCURRENCY") or "4"
    return {"image": image, "concurrency": concurrency}


def get_container_scanner_config() -> dict[str, str]:
    config = read_app_config()
    ct_tool = (config.get("tools") or {}).get("containerScanning") or {}
    image = str(ct_tool.get("dockerImage") or "").strip() or env_source().get("CONTAINER_SCANNER_IMAGE") or "aegis/scanner-container:latest"
    concurrency = str(ct_tool.get("scanConcurrency") or "").strip() or get_app_config_env_value("CONTAINER_SCAN_CONCURRENCY") or "4"
    return {
        "image": image,
        "concurrency": concurrency,
        "nvdEnabled": "true" if ct_tool.get("nvdEnabled", False) else "false",
        "nvdApiKey": str(ct_tool.get("nvdApiKey") or ""),
        "ghsaEnabled": "true" if ct_tool.get("ghsaEnabled", False) else "false",
        "ghsaApiKey": str(ct_tool.get("ghsaApiKey") or ""),
        "argusEnabled": "true" if ct_tool.get("argusEnabled", False) else "false",
        "argusApiKey": str(ct_tool.get("argusApiKey") or ""),
    }


def get_code_scanning_scanner_config() -> dict[str, str]:
    config = read_app_config()
    cs_tool = (config.get("tools") or {}).get("codeScanning") or {}
    image = str(cs_tool.get("dockerImage") or "").strip() or env_source().get("SAST_DOCKER_IMAGE") or "aegis/scanner-code-scanning:latest"
    concurrency = str(cs_tool.get("scanConcurrency") or "").strip() or get_app_config_env_value("SAST_SCAN_CONCURRENCY") or "4"
    rulesets_val = cs_tool.get("rulesets")
    if isinstance(rulesets_val, list):
        rulesets = ",".join(rulesets_val)
    else:
        rulesets = str(rulesets_val or "") or env_source().get("SAST_RULESETS") or "p/owasp-top-ten,p/cwe-top-25"
    return {
        "image": image,
        "concurrency": concurrency,
        "rulesets": rulesets,
        "aiAutoClassifyOnScan": "true" if cs_tool.get("aiAutoClassifyOnScan", False) else "false",
        "aiReviewEnabled": "true" if cs_tool.get("aiReviewEnabled", False) else "false",
        "aiApiKey": str(cs_tool.get("aiApiKey") or ""),
        "aiBaseUrl": str(cs_tool.get("aiBaseUrl") or "https://api.openai.com/v1"),
        "aiModelName": str(cs_tool.get("aiModelName") or "gpt-4o-mini"),
    }


def get_runner_mode() -> str:
    """Return 'local' or 'remote'."""
    config = read_app_config()
    return (config.get("runners") or {}).get("mode", "local")
