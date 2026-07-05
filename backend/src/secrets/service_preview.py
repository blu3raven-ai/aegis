from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable
from urllib.parse import quote

import httpx

from src.shared.config import get_app_config_env_value

CONTEXT_LINES = 8
DEFAULT_GITHUB_API_URL = "https://api.github.com"
DEFAULT_GITHUB_RAW_URL = "https://raw.githubusercontent.com"


@dataclass
class PreviewContext:
    file_path: str | None
    commit: str | None
    line: int | None


@dataclass
class CodePreviewFetchError(Exception):
    status: int
    message: str

    def __str__(self) -> str:
        return self.message


def _as_record(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _nested(record: dict[str, Any], path: list[str]) -> Any:
    current: Any = record
    for segment in path:
        if not isinstance(current, dict):
            return None
        current = current.get(segment)
    return current


def _pick_string(record: dict[str, Any], keys: list[str]) -> str | None:
    for key in keys:
        value = record.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _pick_number(record: dict[str, Any], keys: list[str]) -> int | None:
    for key in keys:
        value = record.get(key)
        if isinstance(value, bool):
            continue
        if isinstance(value, (int, float)) and value == value:
            return int(value)
        if isinstance(value, str) and value.strip():
            try:
                parsed = float(value)
            except ValueError:
                continue
            if parsed == parsed:
                return int(parsed)
    return None


def preview_context_for(finding: dict[str, Any]) -> PreviewContext:
    raw = _as_record(finding.get("raw"))
    git = _as_record(_nested(raw, ["SourceMetadata", "Data", "Git"]))
    file_path = finding.get("filePath") or _pick_string(raw, ["File", "path", "Path", "file"]) or _pick_string(git, ["file"])
    commit = finding.get("commit") or _pick_string(raw, ["Commit", "commit", "commitHash"]) or _pick_string(git, ["commit"])
    line = finding.get("line") if isinstance(finding.get("line"), int) else _pick_number(raw, ["line", "StartLine"]) or _pick_number(git, ["line"])
    return PreviewContext(
        file_path=str(file_path).strip() if isinstance(file_path, str) and file_path.strip() else None,
        commit=str(commit).strip() if isinstance(commit, str) and commit.strip() else None,
        line=line,
    )


def _normalized(value: str | None) -> str:
    return value.strip().lower() if value else ""


def pick_finding_for_preview(
    findings: list[dict[str, Any]],
    repo: str,
    fingerprint: str,
    requested: PreviewContext,
) -> dict[str, Any] | None:
    candidates = [
        finding
        for finding in findings
        if str(finding.get("repository") or "").lower() == repo.lower()
        and str(finding.get("fingerprint") or "") == fingerprint
    ]
    if not candidates:
        return None
    if not requested.commit and not requested.file_path and requested.line is None:
        return candidates[0]

    for finding in candidates:
        context = preview_context_for(finding)
        commit_matches = not requested.commit or _normalized(context.commit) == _normalized(requested.commit)
        file_matches = not requested.file_path or _normalized(context.file_path) == _normalized(requested.file_path)
        line_matches = requested.line is None or context.line == requested.line
        if commit_matches and file_matches and line_matches:
            return finding
    return None


def encode_github_path(file_path: str) -> str:
    return "/".join(quote(segment, safe="") for segment in file_path.split("/"))


def github_headers(token: str) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github.raw",
        "X-GitHub-Api-Version": "2022-11-28",
    }


def github_raw_headers(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}", "Accept": "text/plain"}


def _github_api_url() -> str:
    return (get_app_config_env_value("GITHUB_API_URL") or DEFAULT_GITHUB_API_URL).rstrip("/")


def _github_raw_url() -> str:
    return (get_app_config_env_value("GITHUB_RAW_URL") or DEFAULT_GITHUB_RAW_URL).rstrip("/")


def github_url_for(finding: dict[str, Any]) -> str:
    raw = _as_record(finding.get("raw"))
    raw_link = raw.get("Link")
    if isinstance(raw_link, str) and raw_link.startswith("https://github.com/"):
        return raw_link

    context = preview_context_for(finding)
    file_path = encode_github_path(context.file_path) if context.file_path else ""
    line = f"#L{context.line}" if context.line else ""
    org = quote(str(finding.get("organization") or ""), safe="")
    repo = quote(str(finding.get("repository") or ""), safe="")
    commit = quote(context.commit or "", safe="")
    return f"https://github.com/{org}/{repo}/blob/{commit}/{file_path}{line}"


def build_context_lines(file_content: str, target_line: int) -> list[dict[str, Any]]:
    all_lines = file_content.splitlines()
    if file_content.endswith(("\n", "\r")):
        all_lines.append("")
    start = max(1, target_line - CONTEXT_LINES)
    end = min(len(all_lines), target_line + CONTEXT_LINES)
    return [
        {"number": number, "content": all_lines[number - 1] if number - 1 < len(all_lines) else "", "highlighted": number == target_line}
        for number in range(start, end + 1)
    ]


def _message_for_status(status: int) -> str:
    if status == 404:
        return "File not found at this commit. The file may have been deleted, renamed, or the commit may have been removed by a force push."
    if status in {401, 403}:
        return "Access denied. The repository may be private, archived, or your token may not have access to this content."
    if status == 429:
        return "GitHub API rate limit exceeded. Please wait a moment and try again."
    return f"GitHub returned {status} while loading code preview."


def _raise_for_response(response: httpx.Response) -> None:
    if response.status_code >= 400:
        raise CodePreviewFetchError(response.status_code, _message_for_status(response.status_code))


def _network_error_message(error: Exception) -> str:
    if isinstance(error, httpx.ConnectError):
        return "GitHub connection failed from the server process. Check network/proxy access and try again."
    if isinstance(error, httpx.TimeoutException):
        return "Request timed out while fetching file from GitHub."
    return "Network error while fetching code from GitHub."


def fetch_text(url: str, headers: dict[str, str]) -> str:
    try:
        with httpx.Client(timeout=15.0, follow_redirects=True) as client:
            response = client.get(url, headers=headers)
        _raise_for_response(response)
        return response.text
    except CodePreviewFetchError:
        raise
    except httpx.TimeoutException as error:
        raise CodePreviewFetchError(504, _network_error_message(error)) from error
    except httpx.HTTPError as error:
        raise CodePreviewFetchError(502, _network_error_message(error)) from error


def fetch_commit_date(org: str, repo: str, commit: str, token: str) -> str | None:
    import json as _json

    url = f"{_github_api_url()}/repos/{quote(org, safe='')}/{quote(repo, safe='')}/commits/{quote(commit, safe='')}"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    try:
        with httpx.Client(timeout=10.0, follow_redirects=True) as client:
            response = client.get(url, headers=headers)
        if response.status_code >= 400:
            return None
        data = _json.loads(response.text)
        return data.get("commit", {}).get("author", {}).get("date")
    except Exception:
        return None


def fetch_github_file(finding: dict[str, Any], token: str) -> str:
    context = preview_context_for(finding)
    if not context.file_path or not context.commit:
        raise CodePreviewFetchError(422, "Missing file path or commit for this finding.")

    path = encode_github_path(context.file_path)
    org = quote(str(finding.get("organization") or ""), safe="")
    repo = quote(str(finding.get("repository") or ""), safe="")
    commit = quote(context.commit, safe="")
    url = f"{_github_api_url()}/repos/{org}/{repo}/contents/{path}?ref={commit}"
    raw_url = f"{_github_raw_url()}/{org}/{repo}/{commit}/{path}"

    try:
        return fetch_text(url, github_headers(token))
    except CodePreviewFetchError as error:
        if error.status < 500:
            raise
        return fetch_text(raw_url, github_raw_headers(token))


def build_code_preview_payload(
    org: str,
    repo: str,
    fingerprint: str,
    commit: str | None,
    file_path: str | None,
    line: int | None,
    *,
    get_token_for_org: Callable[[str], str | None],
    read_secrets_snapshot: Callable[[str], dict[str, Any] | None],
) -> tuple[dict[str, Any], int]:
    org = (org or "").strip()
    repo = (repo or "").strip()
    fingerprint = (fingerprint or "").strip()
    requested_commit = (commit or "").strip() or None
    requested_file_path = (file_path or "").strip() or None

    if not org or not repo or not fingerprint:
        return {"error": "Missing org, repo, or fingerprint parameter"}, 400

    token = get_token_for_org(org)
    if not token:
        return {"error": f'GitHub token is not configured for "{org}".'}, 400

    snapshot = read_secrets_snapshot(org)
    findings = snapshot.get("findings") if snapshot else []
    findings = findings if isinstance(findings, list) else []
    finding = pick_finding_for_preview(
        findings,
        repo,
        fingerprint,
        PreviewContext(file_path=requested_file_path, commit=requested_commit, line=line),
    )
    if not finding:
        return {"error": "Finding not found in the latest snapshot for this commit."}, 404

    context = preview_context_for(finding)
    if not context.file_path or not isinstance(context.line, int):
        return {"error": "This finding does not include enough file context to preview code."}, 422

    effective_commit = context.commit or "HEAD"
    commit_is_head = context.commit is None
    enriched = {**finding, "commit": effective_commit}

    try:
        content = fetch_github_file(enriched, token)
    except CodePreviewFetchError as error:
        status = error.status if 400 <= error.status < 600 else 502
        return {"error": error.message}, status

    commit_date_value = fetch_commit_date(
        str(finding.get("organization") or ""),
        str(finding.get("repository") or ""),
        effective_commit,
        token,
    )

    return {
        "organization": finding.get("organization"),
        "repository": finding.get("repository"),
        "filePath": context.file_path,
        "commit": effective_commit,
        "commitDate": commit_date_value,
        "commitIsHead": commit_is_head,
        "line": context.line,
        "githubUrl": github_url_for(enriched),
        "lines": build_context_lines(content, context.line),
    }, 200
