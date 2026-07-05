from __future__ import annotations

import copy
import hashlib
import hmac
import os
import secrets

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse

from src.authz.enforcement.dependencies import Permission
from src.authz.permissions.catalog import MANAGE_SETTINGS
from src.settings.general.schemas import (
    AccountSettingsRequest,
    GeneralSettingsRequest,
    ToolSettingsRequest,
)
from src.shared.config import (
    app_config_to_env,
    read_app_config,
    sync_runtime_env_from_config,
    write_app_config,
)

import logging as _logging

_settings_logger = _logging.getLogger(__name__)


def _validate_nvd_api_key(api_key: str) -> tuple[bool, str]:
    """Validate NVD API key by making a lightweight test request."""
    import httpx

    try:
        resp = httpx.get(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            params={"resultsPerPage": "1"},
            headers={"apiKey": api_key},
            timeout=15.0,
        )
        if resp.status_code == 200:
            return True, ""
        return False, "NVD API key is invalid. Request a free key at nvd.nist.gov."
    except (httpx.TimeoutException, httpx.ConnectError):
        # NVD may throttle/block requests with invalid keys — treat timeout as likely invalid
        return False, "NVD API key could not be verified — the request timed out. The key may be invalid, or NVD may be temporarily unavailable."
    except Exception:
        _settings_logger.debug("NVD key validation failed", exc_info=True)
        return False, "Could not validate NVD API key. Please try again later."


def _validate_ghsa_api_key(api_key: str) -> tuple[bool, str]:
    """Validate GitHub PAT by making a lightweight test request to the advisory API."""
    import httpx

    try:
        resp = httpx.get(
            "https://api.github.com/advisories",
            params={"per_page": "1"},
            headers={
                "Authorization": f"Bearer {api_key}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            },
            timeout=10.0,
        )
        if resp.status_code == 200:
            return True, ""
        if resp.status_code == 401:
            return False, "GitHub PAT is invalid or has expired."
        if resp.status_code == 403:
            return False, "GitHub PAT was rejected. Check that the token is not revoked."
        return False, f"GitHub API returned status {resp.status_code}. Please check your PAT."
    except httpx.TimeoutException:
        return False, "GitHub API is not responding. Please try again later."
    except Exception:
        _settings_logger.debug("GHSA key validation failed", exc_info=True)
        return False, "Could not validate GitHub PAT. Please try again later."

router = APIRouter(prefix="/api/v1/settings", tags=["settings"])

_VALID_TOOLS = {"dependencies_scanning", "container_scanning", "code_scanning", "secret_scanning", "iac_scanning"}
_NUMERIC_KEYS = {"seconds", "page", "days", "concurrency"}

_TOOL_ENV_MAP: dict[str, dict[str, Any]] = {
    "dependencies_scanning": {
        "enabled": "SCA_ENABLED",
        "fields": {},
    },
    "container_scanning": {
        "enabled": "CONTAINER_SCANNING_ENABLED",
        "fields": {},
    },
    "code_scanning": {
        "enabled": "SAST_ENABLED",
        "fields": {},
    },
    "secret_scanning": {
        "enabled": "SECRETS_ENABLED",
        # scanConcurrency is an optional merged field (applied via ui_to_config
        # below), managed centrally under Runners settings rather than per tool.
        "fields": {},
    },
    "iac_scanning": {
        "enabled": "IAC_SECURITY_ENABLED",
        "fields": {},
    },
}


def _hash_dashboard_password(password: str) -> str:
    salt = os.urandom(16)
    key = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=16384, r=8, p=1, dklen=64)
    return f"scrypt:v1:{salt.hex()}:{key.hex()}"


def _passwords_match(input_pw: str, stored_pw: str) -> bool:
    if stored_pw.startswith("scrypt:v1:"):
        parts = stored_pw.split(":")
        if len(parts) != 4:
            return False
        salt = bytes.fromhex(parts[2])
        stored_key = bytes.fromhex(parts[3])
        input_key = hashlib.scrypt(input_pw.encode("utf-8"), salt=salt, n=16384, r=8, p=1, dklen=64)
        return hmac.compare_digest(input_key, stored_key)
    match = hmac.compare_digest(input_pw.encode(), stored_pw.encode())
    if match and stored_pw:
        _settings_logger.warning(
            "[security] Auto-upgrading legacy plaintext dashboard password to scrypt hash"
        )
        new_hash = _hash_dashboard_password(input_pw)
        try:
            config = read_app_config()
            config.setdefault("dashboard", {})["password"] = new_hash
            write_app_config(config, "settings.password_auto_upgraded")
        except Exception:
            _settings_logger.exception("[security] Failed to auto-upgrade plaintext password")
    return match


def _safe_config(config: dict[str, Any]) -> dict[str, Any]:
    result = copy.deepcopy(config)
    dashboard = result.get("dashboard")
    if isinstance(dashboard, dict):
        dashboard["password"] = ""
        dashboard["sessionSecret"] = ""
    tools = result.get("tools")
    if isinstance(tools, dict):
        secret_scanning_tool = tools.get("secret_scanning")
        if isinstance(secret_scanning_tool, dict) and secret_scanning_tool.get("aiApiKey"):
            secret_scanning_tool["aiApiKey"] = "[redacted]"
        for tool_name in ("dependencies_scanning", "container_scanning"):
            tool_dict = tools.get(tool_name)
            if not isinstance(tool_dict, dict):
                continue
            if tool_dict.get("nvdApiKey"):
                tool_dict["nvdApiKeyHint"] = tool_dict["nvdApiKey"][-4:] if len(tool_dict["nvdApiKey"]) > 4 else ""
                tool_dict["nvdApiKey"] = "[redacted]"
            if tool_dict.get("ghsaApiKey"):
                tool_dict["ghsaApiKeyHint"] = tool_dict["ghsaApiKey"][-4:] if len(tool_dict["ghsaApiKey"]) > 4 else ""
                tool_dict["ghsaApiKey"] = "[redacted]"

    return result


def _api_error(message: str, status_code: int) -> HTTPException:
    return HTTPException(status_code=status_code, detail=message)


def _ok_response() -> JSONResponse:
    return JSONResponse({"ok": True}, status_code=200)


def _existing_env() -> dict[str, str]:
    return app_config_to_env(read_app_config())


def _validate_password_change(
    existing_password: str,
    body: AccountSettingsRequest,
) -> tuple[bool, str] | tuple[None, None]:
    password_change_requested = bool(
        body.current_password or body.new_password or body.confirm_new_password
    )
    if not password_change_requested:
        return None, None

    if not body.current_password:
        return False, "Current password is required to change password."
    if not body.new_password:
        return False, "New password is required."
    if not body.confirm_new_password:
        return False, "Please re-enter the new password."
    if body.new_password != body.confirm_new_password:
        return False, "New password and confirmation do not match."
    if not existing_password:
        return False, "No existing dashboard password found. Re-run setup."
    if not _passwords_match(body.current_password, existing_password):
        return False, "Current password is incorrect."
    return True, body.new_password



@router.get("")
def get_settings(
    request: Request,
    _: None = Depends(Permission(MANAGE_SETTINGS)),
) -> dict[str, Any]:
    return _safe_config(read_app_config())


@router.patch("/general")
async def save_general_settings(
    request: Request,
    body: GeneralSettingsRequest,
    _: None = Depends(Permission(MANAGE_SETTINGS)),
) -> JSONResponse:
    username = body.username.strip()
    if not username:
        raise _api_error("Dashboard username is required.", 400)

    config = read_app_config()
    config.setdefault("dashboard", {})["username"] = username
    config["dashboard"]["sessionSecret"] = (
        str(config["dashboard"].get("sessionSecret") or "") or secrets.token_hex(32)
    )
    write_app_config(config, "settings.general.updated")
    sync_runtime_env_from_config(config)
    return _ok_response()


@router.patch("/account")
def save_account_settings(
    request: Request,
    body: AccountSettingsRequest,
    _: None = Depends(Permission(MANAGE_SETTINGS)),
) -> JSONResponse:
    username = body.username.strip()
    if not username:
        raise _api_error("Dashboard username is required.", 400)

    existing_env = _existing_env()
    stored_password = existing_env.get("ADMIN_PASSWORD", "")
    validation_ok, password_value = _validate_password_change(stored_password, body)
    if validation_ok is False:
        raise _api_error(str(password_value), 400)

    config = read_app_config()
    config.setdefault("dashboard", {})["username"] = username
    if validation_ok:
        config["dashboard"]["password"] = _hash_dashboard_password(password_value)
    config["dashboard"]["sessionSecret"] = (
        str(config["dashboard"].get("sessionSecret") or "") or secrets.token_hex(32)
    )
    write_app_config(config, "settings.account.updated")
    sync_runtime_env_from_config(config)
    return _ok_response()


@router.patch("/tools/{tool}")
async def save_tool_settings(
    request: Request,
    tool: str,
    body: ToolSettingsRequest,
    _: None = Depends(Permission(MANAGE_SETTINGS)),
) -> JSONResponse:
    if tool not in _VALID_TOOLS:
        raise _api_error(f"Unknown tool: {tool}. Must be one of: {', '.join(sorted(_VALID_TOOLS))}.", 422)

    mapping = _TOOL_ENV_MAP[tool]
    config = read_app_config()

    for ui_key in mapping["fields"]:
        value = body.settings.get(ui_key, "").strip()
        if not value:
            raise _api_error(f"Missing value for {ui_key}.", 400)
        if any(kw in ui_key.lower() for kw in _NUMERIC_KEYS):
            try:
                numeric = float(value)
            except ValueError:
                raise _api_error(f"{ui_key} must be a positive number.", 400)
            if numeric <= 0:
                raise _api_error(f"{ui_key} must be a positive number.", 400)

    tools = config.setdefault("tools", {})
    tool_config = tools.setdefault(tool, {})
    tool_config["enabled"] = body.enabled

    if tool == "secret_scanning":
        if "aiReviewEnabled" in body.settings:
            tool_config["aiReviewEnabled"] = (
                str(body.settings.get("aiReviewEnabled") or "").strip().lower() == "true"
            )
        if "aiApiKey" in body.settings:
            submitted_ai_key = str(body.settings.get("aiApiKey") or "").strip()
            existing_ai_key = str(tool_config.get("aiApiKey") or "").strip()
            if submitted_ai_key == "[redacted]":
                tool_config["aiApiKey"] = existing_ai_key
            else:
                tool_config["aiApiKey"] = submitted_ai_key

    if tool in ("dependencies_scanning", "container_scanning"):
        # NVD toggle
        tool_config["nvdEnabled"] = str(body.settings.get("nvdEnabled") or "true").strip().lower() == "true"
        # NVD API key — preserve if "[redacted]", clear if empty, validate if new
        submitted_nvd_key = str(body.settings.get("nvdApiKey") or "").strip()
        if submitted_nvd_key == "[redacted]":
            pass  # preserve existing
        elif not submitted_nvd_key:
            tool_config.pop("nvdApiKey", None)
        else:
            valid, err = _validate_nvd_api_key(submitted_nvd_key)
            if not valid:
                raise _api_error(err, 400)
            tool_config["nvdApiKey"] = submitted_nvd_key

        # GHSA toggle
        ghsa_enabled = str(body.settings.get("ghsaEnabled") or "true").strip().lower() == "true"
        tool_config["ghsaEnabled"] = ghsa_enabled
        # GHSA API key — preserve if "[redacted]", clear if empty, validate if new
        submitted_ghsa_key = str(body.settings.get("ghsaApiKey") or "").strip()
        if submitted_ghsa_key == "[redacted]":
            pass  # preserve existing
        elif not submitted_ghsa_key:
            tool_config.pop("ghsaApiKey", None)
        else:
            valid, err = _validate_ghsa_api_key(submitted_ghsa_key)
            if not valid:
                raise _api_error(err, 400)
            tool_config["ghsaApiKey"] = submitted_ghsa_key

        # Release-age enrichment — opt-in (off by default); reaches deps.dev.
        if "releaseAgeEnabled" in body.settings:
            tool_config["releaseAgeEnabled"] = (
                str(body.settings.get("releaseAgeEnabled") or "false").strip().lower() == "true"
            )
        if "releaseAgeThresholdDays" in body.settings:
            try:
                days = int(str(body.settings.get("releaseAgeThresholdDays")).strip())
            except (TypeError, ValueError):
                raise _api_error("releaseAgeThresholdDays must be an integer", 400)
            tool_config["releaseAgeThresholdDays"] = str(max(1, min(days, 3650)))

        # Base-image tag recommendation — opt-in; lists tags from the registry.
        if "baseImageTagsEnabled" in body.settings:
            tool_config["baseImageTagsEnabled"] = (
                str(body.settings.get("baseImageTagsEnabled") or "false").strip().lower() == "true"
            )
        # Base-image upgrade recommendation — opt-in; SBOM-scans candidate tags.
        if "baseImageRecommendEnabled" in body.settings:
            tool_config["baseImageRecommendEnabled"] = (
                str(body.settings.get("baseImageRecommendEnabled") or "false").strip().lower() == "true"
            )

    ui_to_config = {
        "dependencies_scanning": {
            "scanConcurrency": "scanConcurrency",
        },
        "container_scanning": {
            "scanConcurrency": "scanConcurrency",
        },
        "code_scanning": {
            "scanConcurrency": "scanConcurrency",
        },
        "secret_scanning": {
            "scanConcurrency": "scanConcurrency",
        },
        "iac_scanning": {
        },
    }
    for ui_key, config_key in ui_to_config[tool].items():
        if ui_key not in body.settings:
            continue
        tool_config[config_key] = str(body.settings.get(ui_key) or "").strip()

    write_app_config(config, f"settings.{tool}.updated")
    sync_runtime_env_from_config(config)

    from src.notifications.emitter import notify_settings_changed
    from src.authz.teams.access import actor_user_id
    notify_settings_changed(tool, actor_user_id(request) or "unknown")

    return _ok_response()
