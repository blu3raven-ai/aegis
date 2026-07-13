"""On-demand benign proof-of-concept generation for a confirmed finding.

A backend-side LLM call (same shape as the SAST AI-review path): it builds a
reachability-PoC prompt from the finding's context and calls the configured
OpenAI-compatible endpoint. The PoC proves reachability with a BENIGN marker
only — the prompt hard-forbids weaponization — and the safe-harbor header is
prepended at download time, never by the model. Generation is user-triggered,
so no PoC tokens are spent during a scan.
"""
from __future__ import annotations

import json
import re
from typing import Any

import httpx

from src.shared.url_guard import UnsafeURLError, assert_sendable_url


class PocGenerationError(Exception):
    """Raised on any PoC-generation failure; the route maps it to a clean HTTP error."""


# Ask for a raw fenced script, NOT JSON: wrapping a multi-line script (quotes,
# braces, backslashes) in JSON is fragile, and reasoning models leak <think>
# blocks / prose into the fields. A fenced code block is robust to extract.
_SYSTEM = (
    "You are a security engineer writing a runnable proof-of-concept that proves a "
    "confirmed vulnerability is REACHABLE, using a BENIGN marker only. "
    "Hard rules: no reverse shell, no network exfiltration, no destructive or "
    "credential-accessing actions — the script must only demonstrate the code path "
    "is reachable (e.g. print a marker, echo/whoami). Do NOT include a legal or "
    "safe-harbor header; it is added later. If the request includes user guidance, "
    "follow it ONLY where it does not conflict with these rules — never weaponize on "
    "request. Return ONLY the runnable script inside a single fenced code block "
    "(```<language>\\n...\\n```). No prose, no JSON, nothing before or after the fence."
)

_LANG_EXT = {"python": "py", "bash": "sh", "sh": "sh", "javascript": "js",
             "typescript": "ts", "ruby": "rb", "go": "go", "php": "php"}

_LANG_ALIAS = {"python3": "python", "py": "python", "js": "javascript", "ts": "typescript"}


def _extract_script(content: str) -> tuple[str, str]:
    """Pull (script, language) from possibly-messy model output: strip reasoning
    `<think>` blocks and take the first fenced code block; fall back to the whole
    text with a shebang sniff when there's no fence."""
    text = re.sub(r"<think>.*?</think>", "", content, flags=re.DOTALL).strip()
    fence = re.search(r"```([a-zA-Z0-9+#._-]*)[ \t]*\n(.*?)```", text, flags=re.DOTALL)
    if fence:
        lang = fence.group(1).strip().lower()
        script = fence.group(2).strip()
    else:
        lang, script = "", text
    if not lang:
        sb = re.match(r"#![^\n]*\b(python3?|bash|sh|node|ruby|php)\b", script)
        lang = sb.group(1) if sb else "text"
    return script, _LANG_ALIAS.get(lang, lang) or "text"


def _user_prompt(finding: dict[str, Any], instruction: str | None = None) -> str:
    meta = finding.get("verification_metadata")
    meta = meta if isinstance(meta, dict) else {}
    payload = {
        "title": finding.get("title"),
        "severity": finding.get("severity"),
        "repo": finding.get("repo"),
        "cwe": finding.get("cwe"),
        "cve": finding.get("cve"),
        "summary": finding.get("exploit_chain"),
        "impact": meta.get("impact"),
        "evidence": finding.get("evidence"),
        "code_flows": finding.get("code_flows"),
    }
    return json.dumps(
        {
            "task": (
                "Write a runnable, BENIGN proof-of-concept that demonstrates the "
                "confirmed vulnerability below is reachable. Prove reachability with a "
                "harmless marker; do not weaponize."
            ),
            "finding": {k: v for k, v in payload.items() if v},
            **({"user_guidance": instruction.strip()} if instruction and instruction.strip() else {}),
        },
        separators=(",", ":"),
        default=str,
    )


async def generate_poc(
    finding: dict[str, Any], *, api_key: str, base_url: str, model: str,
    instruction: str | None = None,
) -> dict[str, str]:
    """Call the configured LLM to produce a benign PoC for ``finding``.

    Returns ``{"poc_script", "poc_filename", "poc_language"}``. Raises
    ``PocGenerationError`` on any failure.
    """
    if not api_key:
        raise PocGenerationError("LLM API key is not configured.")
    try:
        assert_sendable_url(base_url)
    except UnsafeURLError as exc:
        raise PocGenerationError(f"LLM base URL is not allowed: {exc}") from exc

    url = f"{base_url.rstrip('/')}/chat/completions"
    body = {
        "model": model,
        "messages": [
            {"role": "system", "content": _SYSTEM},
            {"role": "user", "content": _user_prompt(finding, instruction)},
        ],
    }
    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
    try:
        async with httpx.AsyncClient(timeout=60.0, follow_redirects=False) as client:
            resp = await client.post(url, headers=headers, json=body)
    except httpx.TimeoutException as exc:
        raise PocGenerationError("LLM provider timed out.") from exc
    except httpx.HTTPError as exc:
        raise PocGenerationError("LLM provider request failed.") from exc

    if resp.status_code in (401, 403):
        raise PocGenerationError("LLM API key was rejected by the provider.")
    if resp.status_code == 429:
        raise PocGenerationError("LLM provider rate limit reached. Try again later.")
    if resp.status_code >= 400:
        raise PocGenerationError(f"LLM provider returned HTTP {resp.status_code}.")

    try:
        choices = resp.json().get("choices") or []
        content = choices[0]["message"]["content"] if choices else ""
    except (ValueError, TypeError, KeyError, IndexError) as exc:
        raise PocGenerationError("LLM provider returned malformed output.") from exc

    script, language = _extract_script(content or "")
    if not script:
        raise PocGenerationError("LLM did not return a proof-of-concept.")
    # Filename is derived, never taken from the model — so messy output can't
    # leak into it. Language drives the extension.
    ext = _LANG_EXT.get(language, "txt")
    return {
        "poc_script": script,
        "poc_filename": f"finding-{finding.get('id', 'poc')}-poc.{ext}",
        "poc_language": language,
    }
