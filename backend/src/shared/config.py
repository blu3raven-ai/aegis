from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from src.shared.paths import repo_root
from src.shared.providers.base import (
    UnknownProvider,
    get_image_registry,
    get_repo_provider,
)
# Force-register built-in providers via import side effect
import src.shared.providers.repos  # noqa: F401
import src.shared.providers.registries  # noqa: F401


def get_session_secret() -> str:
    """Return the SESSION_SECRET env var. Fails loudly if unset or empty."""
    secret = os.environ.get("SESSION_SECRET", "")
    if not secret:
        raise RuntimeError(
            "SESSION_SECRET environment variable is required (32+ bytes recommended). "
            "Set it in .env or your secrets manager."
        )
    return secret


# Loopback and the internal compose service name are deployment-topology
# constants: local access and service-to-service traffic (the runner reaching
# the backend at http://aegis:3000) always rely on them. They are trusted
# unconditionally so operators only ever configure their *public* hostname(s)
# via ALLOWED_HOSTS — the internal name can never be accidentally dropped.
_BASELINE_HOSTS = ("localhost", "127.0.0.1", "aegis")


def get_allowed_hosts() -> list[str]:
    """Hosts the app is willing to serve.

    Always trusts loopback and the internal service name (see ``_BASELINE_HOSTS``).
    Set ``ALLOWED_HOSTS`` to a comma-separated list to additionally trust public
    hostnames (e.g. ``scan.example.com``); those are merged onto the baseline.
    """
    raw = os.getenv("ALLOWED_HOSTS", "")
    extra = [h.strip() for h in raw.split(",") if h.strip()]
    # Dedup while preserving order, baseline first.
    return list(dict.fromkeys([*_BASELINE_HOSTS, *extra]))

ENV_PATH = repo_root() / ".env.local"

# Keys that must be redacted when logging or displaying config
_SENSITIVE_KEYS = {
    "aiApiKey", "nvdApiKey", "ghsaApiKey",
    "argusApiKey", "argusEndpoint", "argusWebhookSecret",
    "githubWebhookSecret", "gitlabWebhookSecret", "bitbucketWebhookSecret",
}


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
            "dependencies_scanning": {
                "enabled": _to_bool(env.get("SCA_ENABLED"), False),
                "scanConcurrency": env.get("SCA_SCAN_CONCURRENCY") or "4",
                "nvdEnabled": env.get("SCA_NVD_ENABLED", "").lower() != "false",
                "nvdApiKey": env.get("SCA_NVD_API_KEY") or "",
                "ghsaEnabled": env.get("SCA_GHSA_ENABLED", "").lower() == "true",
                "ghsaApiKey": env.get("SCA_GHSA_API_KEY") or "",
                "releaseAgeEnabled": env.get("SCA_RELEASE_AGE_ENABLED", "").lower() == "true",
                "releaseAgeThresholdDays": env.get("SCA_RELEASE_AGE_THRESHOLD_DAYS") or "90",
            },
            "container_scanning": {
                "enabled": _to_bool(env.get("CONTAINER_SCANNING_ENABLED"), False),
                "scanConcurrency": env.get("CONTAINER_SCAN_CONCURRENCY") or "4",
                "nvdEnabled": env.get("CONTAINER_SCANNING_NVD_ENABLED", "true").lower() != "false",
                "nvdApiKey": env.get("CONTAINER_SCANNING_NVD_API_KEY") or "",
                "ghsaEnabled": env.get("CONTAINER_SCANNING_GHSA_ENABLED", "false").lower() == "true",
                "ghsaApiKey": env.get("CONTAINER_SCANNING_GHSA_API_KEY") or "",
                "argusEnabled": env.get("CONTAINER_SCANNING_ARGUS_ENABLED", "false").lower() == "true",
                "argusApiKey": env.get("CONTAINER_SCANNING_ARGUS_API_KEY") or "",
                "releaseAgeEnabled": env.get("CONTAINER_SCANNING_RELEASE_AGE_ENABLED", "").lower() == "true",
                "releaseAgeThresholdDays": env.get("CONTAINER_SCANNING_RELEASE_AGE_THRESHOLD_DAYS") or "90",
                "baseImageTagsEnabled": env.get("CONTAINER_SCANNING_BASE_IMAGE_TAGS_ENABLED", "").lower() == "true",
                "baseImageRecommendEnabled": env.get("CONTAINER_SCANNING_BASE_IMAGE_RECOMMEND_ENABLED", "").lower() == "true",
            },
            "code_scanning": {
                "enabled": _to_bool(env.get("SAST_ENABLED"), False),
                "scanConcurrency": env.get("SAST_SCAN_CONCURRENCY") or "4",
            },
            "secret_scanning": {
                "enabled": _to_bool(env.get("SECRETS_ENABLED"), False),
                "scanConcurrency": env.get("SECRET_SCANNER_CONCURRENCY") or env.get("SECRETS_SCAN_CONCURRENCY") or "4",
                "aiReviewEnabled": _to_bool(env.get("SECRETS_AI_REVIEW_ENABLED"), False),
                "aiApiKey": env.get("SECRETS_AI_API_KEY") or "",
            },
            "iac_scanning": {
                "enabled": _to_bool(env.get("IAC_SECURITY_ENABLED"), False),
            },
        },
    }


def _normalize_config(value: dict[str, Any] | None, fallback: dict[str, Any]) -> dict[str, Any]:
    value = value if isinstance(value, dict) else {}

    dashboard = value.get("dashboard") if isinstance(value.get("dashboard"), dict) else {}
    auth_security = value.get("authSecurity") if isinstance(value.get("authSecurity"), dict) else {}
    tools = value.get("tools") if isinstance(value.get("tools"), dict) else {}
    dependencies = tools.get("dependencies_scanning") if isinstance(tools.get("dependencies_scanning"), dict) else {}
    container_scanning_cfg = tools.get("container_scanning") if isinstance(tools.get("container_scanning"), dict) else {}
    code_scanning = tools.get("code_scanning") if isinstance(tools.get("code_scanning"), dict) else {}
    secrets = tools.get("secret_scanning") if isinstance(tools.get("secret_scanning"), dict) else {}
    iac_security = tools.get("iac_scanning") if isinstance(tools.get("iac_scanning"), dict) else {}

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
            "dependencies_scanning": {
                "enabled": dependencies.get("enabled", fallback["tools"]["dependencies_scanning"]["enabled"]),
                "scanConcurrency": dependencies.get("scanConcurrency", fallback["tools"]["dependencies_scanning"]["scanConcurrency"]),
                "nvdEnabled": dependencies.get("nvdEnabled", fallback["tools"]["dependencies_scanning"]["nvdEnabled"]),
                "nvdApiKey": dependencies.get("nvdApiKey", fallback["tools"]["dependencies_scanning"]["nvdApiKey"]),
                "ghsaEnabled": dependencies.get("ghsaEnabled", fallback["tools"]["dependencies_scanning"]["ghsaEnabled"]),
                "ghsaApiKey": dependencies.get("ghsaApiKey", fallback["tools"]["dependencies_scanning"]["ghsaApiKey"]),
                "releaseAgeEnabled": dependencies.get("releaseAgeEnabled", fallback["tools"]["dependencies_scanning"]["releaseAgeEnabled"]),
                "releaseAgeThresholdDays": dependencies.get("releaseAgeThresholdDays", fallback["tools"]["dependencies_scanning"]["releaseAgeThresholdDays"]),
            },
            "container_scanning": {
                "enabled": container_scanning_cfg.get("enabled", fallback["tools"]["container_scanning"]["enabled"]),
                "scanConcurrency": container_scanning_cfg.get("scanConcurrency", fallback["tools"]["container_scanning"]["scanConcurrency"]),
                "nvdEnabled": container_scanning_cfg.get("nvdEnabled", fallback["tools"]["container_scanning"]["nvdEnabled"]),
                "nvdApiKey": container_scanning_cfg.get("nvdApiKey", fallback["tools"]["container_scanning"]["nvdApiKey"]),
                "ghsaEnabled": container_scanning_cfg.get("ghsaEnabled", fallback["tools"]["container_scanning"]["ghsaEnabled"]),
                "ghsaApiKey": container_scanning_cfg.get("ghsaApiKey", fallback["tools"]["container_scanning"]["ghsaApiKey"]),
                "argusEnabled": container_scanning_cfg.get("argusEnabled", fallback["tools"]["container_scanning"]["argusEnabled"]),
                "argusApiKey": container_scanning_cfg.get("argusApiKey", fallback["tools"]["container_scanning"]["argusApiKey"]),
                "releaseAgeEnabled": container_scanning_cfg.get("releaseAgeEnabled", fallback["tools"]["container_scanning"]["releaseAgeEnabled"]),
                "releaseAgeThresholdDays": container_scanning_cfg.get("releaseAgeThresholdDays", fallback["tools"]["container_scanning"]["releaseAgeThresholdDays"]),
                "baseImageTagsEnabled": container_scanning_cfg.get("baseImageTagsEnabled", fallback["tools"]["container_scanning"]["baseImageTagsEnabled"]),
                "baseImageRecommendEnabled": container_scanning_cfg.get("baseImageRecommendEnabled", fallback["tools"]["container_scanning"]["baseImageRecommendEnabled"]),
            },
            "code_scanning": {
                "enabled": code_scanning.get("enabled", fallback["tools"]["code_scanning"]["enabled"]),
                "scanConcurrency": code_scanning.get("scanConcurrency", fallback["tools"]["code_scanning"]["scanConcurrency"]),
            },
            "secret_scanning": {
                "enabled": secrets.get("enabled", fallback["tools"]["secret_scanning"]["enabled"]),
                "scanConcurrency": secrets.get(
                    "scanConcurrency", fallback["tools"]["secret_scanning"]["scanConcurrency"]
                ),
                "aiReviewEnabled": secrets.get("aiReviewEnabled", fallback["tools"]["secret_scanning"]["aiReviewEnabled"]),
                "aiApiKey": secrets.get("aiApiKey", fallback["tools"]["secret_scanning"]["aiApiKey"]),
            },
            "iac_scanning": {
                "enabled": iac_security.get("enabled", fallback["tools"]["iac_scanning"]["enabled"]),
            },
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

    dependencies = tools.get("dependencies_scanning") if isinstance(tools.get("dependencies_scanning"), dict) else {}
    env["SCA_ENABLED"] = "true" if dependencies.get("enabled", False) else "false"
    env["SCA_SCAN_CONCURRENCY"] = str(dependencies.get("scanConcurrency") or "4")

    container_scanning_cfg = tools.get("container_scanning") if isinstance(tools.get("container_scanning"), dict) else {}
    env["CONTAINER_SCANNING_ENABLED"] = "true" if container_scanning_cfg.get("enabled", False) else "false"
    env["CONTAINER_SCAN_CONCURRENCY"] = str(container_scanning_cfg.get("scanConcurrency") or "4")

    code_scanning = tools.get("code_scanning") if isinstance(tools.get("code_scanning"), dict) else {}
    env["SAST_ENABLED"] = "true" if code_scanning.get("enabled", False) else "false"
    env["SAST_SCAN_CONCURRENCY"] = str(code_scanning.get("scanConcurrency") or "4")

    secrets = tools.get("secret_scanning") if isinstance(tools.get("secret_scanning"), dict) else {}
    env["SECRETS_ENABLED"] = "true" if secrets.get("enabled", True) else "false"
    scan_concurrency = str(secrets.get("scanConcurrency") or "4")
    env["SECRET_SCANNER_CONCURRENCY"] = scan_concurrency
    env["SECRETS_SCAN_CONCURRENCY"] = scan_concurrency
    env["SECRETS_AI_REVIEW_ENABLED"] = "true" if secrets.get("aiReviewEnabled", False) else "false"
    env["SECRETS_AI_API_KEY"] = str(secrets.get("aiApiKey") or "")

    iac_security = tools.get("iac_scanning") if isinstance(tools.get("iac_scanning"), dict) else {}
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

        for tool_name in ("code_scanning", "dependencies_scanning", "container_scanning", "secret_scanning"):
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
    from src.settings.audit_stream.service import record_event
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
    from src.sources.store import list_connections_with_secrets
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


def get_token_for_org(org: str) -> str:
    """Return the token of the first connected source matching this org.

    Provider-agnostic: matches connections from any source_type
    (github, gitlab, bitbucket, etc.) by their `auth.orgOrOwner` value.
    """
    key = org.lower()
    for conn in _read_source_connections():
        if conn.get("status") != "connected":
            continue
        auth = conn.get("auth") if isinstance(conn.get("auth"), dict) else {}
        conn_org = (auth.get("orgOrOwner") or "").strip()
        if conn_org and conn_org.lower() == key and auth.get("token"):
            return str(auth["token"])
    return ""


def get_source_type_for_org(org: str, category: str) -> str:
    """Return the source_type of the first connected source matching (org, category).

    `category` is one of "code-repositories" or "container-images". Used by the
    scheduler dispatch to populate ScanContext.source_type for the right
    connection — code scanners need "github"/"gitlab", container scanners need
    "ghcr"/"dockerhub"/etc.

    Returns "" if no matching connection exists.
    """
    key = org.lower()
    for conn in _read_source_connections():
        if conn.get("status") != "connected":
            continue
        if conn.get("category") != category:
            continue
        auth = conn.get("auth") if isinstance(conn.get("auth"), dict) else {}
        conn_org = (auth.get("orgOrOwner") or "").strip()
        if conn_org and conn_org.lower() == key:
            return str(conn.get("source_type") or "")
    return ""


def get_instance_url_for_org(org: str, source_type: str) -> str:
    """Return the instanceUrl of the first connected code-repository connection
    matching (org, source_type).

    Empty for SaaS providers (github.com / gitlab.com / bitbucket.org) and when
    no matching connection exists. Callers pass it to a repo provider's
    clone_url so self-hosted (GHE / self-managed GitLab / Gitea) clones target
    the right host instead of the SaaS default.
    """
    key = org.lower()
    for conn in _read_source_connections():
        if conn.get("status") != "connected":
            continue
        if conn.get("category") != "code-repositories":
            continue
        if str(conn.get("source_type") or "") != source_type:
            continue
        auth = conn.get("auth") if isinstance(conn.get("auth"), dict) else {}
        conn_org = (auth.get("orgOrOwner") or "").strip()
        if conn_org and conn_org.lower() == key:
            return str(auth.get("instanceUrl") or "")
    return ""


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
        # Respect the connection's scope: a cherry-pick ("selected") connection
        # covers only includedItems; "all-except-excluded" drops excludedItems;
        # anything else covers everything discovered.
        if scan_scope == "selected":
            source_items = conn.get("includedItems") or []
            excluded: set[str] = set()
        else:
            source_items = conn.get("discoveredItems") or []
            excluded = set(conn.get("excludedItems") or []) if scan_scope == "all-except-excluded" else set()

        repo_urls: list[str] = []
        container_images: list[str] = []
        registry_token = ""
        instance_url = (auth.get("instanceUrl") or "").rstrip("/")

        for item in source_items:
            if not isinstance(item, str) or not item.strip() or item in excluded:
                continue
            name = item.strip()

            if category == "code-repositories":
                repo_path = name if "/" in name else f"{conn_org}/{name}"
                org_part, _, repo_part = repo_path.partition("/")
                try:
                    repo_provider = get_repo_provider(source_type)
                except UnknownProvider:
                    continue  # silently skip unknown source_types — matches old behavior
                repo_urls.append(repo_provider.clone_url(org_part, repo_part, instance_url))

            elif category == "container-images":
                name_without_tag = name.split(":")[0]
                if "." not in name_without_tag.split("/")[0]:
                    try:
                        registry = get_image_registry(source_type)
                    except UnknownProvider:
                        continue  # silently skip unknown source_types
                    name = registry.normalize_image_ref(conn_org, name, instance_url)
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
    secret_scanning_tool = (config.get("tools") or {}).get("secret_scanning") or {}
    concurrency = str(secret_scanning_tool.get("scanConcurrency") or "").strip() or get_app_config_env_value("SECRET_SCANNER_CONCURRENCY") or get_app_config_env_value("SECRETS_SCAN_CONCURRENCY") or "4"
    return {
        "concurrency": concurrency,
    }


def get_dependencies_scanner_config() -> dict[str, str]:
    config = read_app_config()
    deps_tool = (config.get("tools") or {}).get("dependencies_scanning") or {}
    concurrency = str(deps_tool.get("scanConcurrency") or "").strip() or get_app_config_env_value("SCA_SCAN_CONCURRENCY") or "4"
    return {
        "concurrency": concurrency,
        "releaseAgeEnabled": "true" if deps_tool.get("releaseAgeEnabled", False) else "false",
        "releaseAgeThresholdDays": str(deps_tool.get("releaseAgeThresholdDays") or "90"),
    }


def get_container_scanner_config() -> dict[str, str]:
    config = read_app_config()
    ct_tool = (config.get("tools") or {}).get("container_scanning") or {}
    concurrency = str(ct_tool.get("scanConcurrency") or "").strip() or get_app_config_env_value("CONTAINER_SCAN_CONCURRENCY") or "4"
    return {
        "concurrency": concurrency,
        # NVD enrichment is on by default — matches the dependencies scanner and
        # the container env fallback; the keyless NVD API still works (rate-limited)
        # and enrichment failures are isolated at the ingest call site.
        "nvdEnabled": "true" if ct_tool.get("nvdEnabled", True) else "false",
        "nvdApiKey": str(ct_tool.get("nvdApiKey") or ""),
        "ghsaEnabled": "true" if ct_tool.get("ghsaEnabled", False) else "false",
        "ghsaApiKey": str(ct_tool.get("ghsaApiKey") or ""),
        "argusEnabled": "true" if ct_tool.get("argusEnabled", False) else "false",
        "argusApiKey": str(ct_tool.get("argusApiKey") or ""),
        "releaseAgeEnabled": "true" if ct_tool.get("releaseAgeEnabled", False) else "false",
        "releaseAgeThresholdDays": str(ct_tool.get("releaseAgeThresholdDays") or "90"),
        "baseImageTagsEnabled": "true" if ct_tool.get("baseImageTagsEnabled", False) else "false",
        "baseImageRecommendEnabled": "true" if ct_tool.get("baseImageRecommendEnabled", False) else "false",
    }


def get_code_scanning_scanner_config() -> dict[str, str]:
    config = read_app_config()
    cs_tool = (config.get("tools") or {}).get("code_scanning") or {}
    concurrency = str(cs_tool.get("scanConcurrency") or "").strip() or get_app_config_env_value("SAST_SCAN_CONCURRENCY") or "4"
    return {
        "concurrency": concurrency,
    }


