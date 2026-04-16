"""SAST AI Review — OpenAI-compatible assessment of SAST findings.

Redesigned with:
- Severity-based tiering (deep/light/skip)
- CWE-grouped micro-rubric checklists
- Chain-of-thought reasoning field
- Dataflow trace + code context in deep-tier prompts
"""
from __future__ import annotations

import json
import ipaddress
import socket
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx

VALID_VERDICTS = {"true_positive", "likely_false_positive", "needs_review"}

_PATH_FEASIBILITY_QUESTION = (
    "Is this code path actually reachable in production — "
    "or is it behind a debug flag, unreachable conditional, or dead code?"
)

_CWE_GROUPS: dict[str, dict] = {
    "injection": {
        "cwe_numbers": {"89", "78", "77", "88"},
        "name": "Injection",
        "questions": [
            "Is the flagged value user-controlled or derived from external input?",
            "Is there parameterization, escaping, or sanitization applied between the source and the sink?",
            "Does the dataflow trace confirm untainted flow to the sink?",
            "Is the language-specific safe API in use (e.g. parameterized queries, subprocess list form)?",
            _PATH_FEASIBILITY_QUESTION,
        ],
    },
    "path": {
        "cwe_numbers": {"22", "23", "73"},
        "name": "Path/Resource Traversal",
        "questions": [
            "Is the path component user-controlled?",
            "Is it validated or canonicalized before use?",
            "Does the language or framework provide a safe path join API that is being used?",
            _PATH_FEASIBILITY_QUESTION,
        ],
    },
    "xss": {
        "cwe_numbers": {"79", "80"},
        "name": "Cross-Site Scripting (XSS)",
        "questions": [
            "Is the output HTML-encoded?",
            "Does user-controlled input reach an HTML rendering sink unsanitized?",
            "Does the templating engine auto-escape by default for this language/framework?",
            _PATH_FEASIBILITY_QUESTION,
        ],
    },
    "deserialization": {
        "cwe_numbers": {"502"},
        "name": "Insecure Deserialization",
        "questions": [
            "Is the deserialized input from an untrusted source?",
            "Is type or schema validation applied before or after deserialization?",
            _PATH_FEASIBILITY_QUESTION,
        ],
    },
    "auth_crypto": {
        "cwe_numbers": {"798", "259", "327", "330"},
        "name": "Authentication/Cryptography",
        "questions": [
            "Is this a hardcoded credential or a placeholder/test value?",
            "Is the algorithm weak in its specific usage context?",
            _PATH_FEASIBILITY_QUESTION,
        ],
    },
    "ssrf": {
        "cwe_numbers": {"918"},
        "name": "Server-Side Request Forgery (SSRF)",
        "questions": [
            "Is the URL user-controlled?",
            "Is there an allowlist or scheme restriction applied?",
            _PATH_FEASIBILITY_QUESTION,
        ],
    },
    "generic": {
        "cwe_numbers": set(),
        "name": "Security Finding",
        "questions": [
            "Is the flagged pattern reachable with untrusted input in this context?",
            _PATH_FEASIBILITY_QUESTION,
        ],
    },
}

# Reverse lookup: CWE number string → group key
_CWE_TO_GROUP: dict[str, str] = {
    num: gkey
    for gkey, gdata in _CWE_GROUPS.items()
    for num in gdata["cwe_numbers"]
}

_DEEP_SEVERITIES = frozenset({"critical", "high"})
_LIGHT_SEVERITIES = frozenset({"medium"})


class CodeScanningAiReviewError(Exception):
    pass


def _get_tier(finding: dict[str, Any]) -> str:
    """Return 'deep', 'light', or 'skip' based on finding severity."""
    severity = str(finding.get("severity") or "").lower()
    if severity in _DEEP_SEVERITIES:
        return "deep"
    if severity in _LIGHT_SEVERITIES:
        return "light"
    return "skip"


def _resolve_cwe_group(cwe_list: list[str]) -> dict:
    """Resolve CWE tag list to group definition. Falls back to generic."""
    for cwe_tag in cwe_list:
        num = str(cwe_tag).replace("CWE-", "").strip()
        group_key = _CWE_TO_GROUP.get(num)
        if group_key:
            return _CWE_GROUPS[group_key]
    return _CWE_GROUPS["generic"]


def _validate_ai_base_url(base_url: str) -> str:
    parsed = urlparse(base_url)
    if parsed.scheme not in ("https", "http"):
        raise CodeScanningAiReviewError(f"Invalid AI base URL scheme: {parsed.scheme!r}. Use https://")
    hostname = parsed.hostname
    if not hostname:
        raise CodeScanningAiReviewError("Invalid AI base URL: missing hostname")
    _ALLOWED_AI_HOSTS = {
        "api.openai.com",
        "api.anthropic.com",
        "generativelanguage.googleapis.com",
    }
    if hostname in _ALLOWED_AI_HOSTS:
        return base_url.rstrip("/")
    try:
        for info in socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM):
            addr = info[4][0]
            ip = ipaddress.ip_address(addr)
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
                raise CodeScanningAiReviewError(
                    "AI base URL resolves to a blocked address."
                )
    except socket.gaierror:
        raise CodeScanningAiReviewError(f"Cannot resolve AI base URL hostname: {hostname}")
    return base_url.rstrip("/")


def _schema() -> dict[str, Any]:
    return {
        "type": "object",
        "additionalProperties": False,
        "required": ["reasoning", "verdict", "explanation", "confidence"],
        "properties": {
            "reasoning": {"type": "string"},
            "verdict": {"type": "string", "enum": ["true_positive", "likely_false_positive", "needs_review"]},
            "explanation": {"type": "string"},
            "confidence": {"type": "string", "enum": ["low", "medium", "high"]},
        },
    }


def _prompt(finding: dict[str, Any], tier: str) -> str:
    cwe_list = finding.get("cwe") or []
    group = _resolve_cwe_group(cwe_list)
    language = finding.get("language") or "unknown"
    cwe_label = ", ".join(cwe_list) if cwe_list else "Unknown CWE"

    finding_payload: dict[str, Any] = {
        "rule_id": finding.get("rule_id"),
        "rule_name": finding.get("rule_name"),
        "severity": finding.get("severity"),
        "message": finding.get("message"),
        "file_path": finding.get("file_path"),
        "start_line": finding.get("start_line"),
        "snippet": finding.get("snippet"),
        "fix_suggestion": finding.get("fix_suggestion"),
        "cwe": cwe_list,
        "category": finding.get("category"),
        "file_class": finding.get("file_class") or "source",
    }

    if tier == "deep":
        code_flows = finding.get("code_flows")
        if code_flows:
            finding_payload["code_flows"] = code_flows
        code_window = finding.get("code_window")
        if code_window:
            finding_payload["code_window"] = code_window
        imports = finding.get("imports")
        if imports:
            finding_payload["imports"] = imports

    return json.dumps(
        {
            "task": (
                "Review this SAST finding. Work through each checklist item using the code context "
                "and dataflow trace as evidence. Write your step-by-step reasoning in the 'reasoning' "
                "field, then give your verdict."
            ),
            "language": language,
            "vulnerability_class": f"{group['name']} ({cwe_label})",
            "checklist": group["questions"],
            "finding": finding_payload,
        },
        separators=(",", ":"),
    )


def _validate_review(payload: dict[str, Any]) -> dict[str, Any]:
    reasoning = str(payload.get("reasoning") or "").strip()
    verdict = str(payload.get("verdict") or "").strip()
    if verdict not in VALID_VERDICTS:
        raise CodeScanningAiReviewError("AI response used an unsupported verdict.")
    explanation = str(payload.get("explanation") or "").strip()
    if not explanation:
        raise CodeScanningAiReviewError("AI response missing explanation.")
    confidence = str(payload.get("confidence") or "").strip()
    if confidence not in {"low", "medium", "high"}:
        confidence = "medium"
    return {"reasoning": reasoning, "verdict": verdict, "explanation": explanation, "confidence": confidence}


async def _request_ai_review(
    *,
    api_key: str,
    base_url: str,
    model: str,
    finding: dict[str, Any],
    tier: str,
) -> dict[str, Any]:
    validated_url = _validate_ai_base_url(base_url)
    url = f"{validated_url}/chat/completions"
    body = {
        "model": model,
        "messages": [
            {
                "role": "system",
                "content": (
                    "You are a security expert reviewing SAST findings. "
                    "Think step by step through each checklist item using the code context "
                    "and dataflow trace as evidence. "
                    "Write your reasoning in the 'reasoning' field before committing to a verdict. "
                    "Return JSON only."
                ),
            },
            {"role": "user", "content": _prompt(finding, tier)},
        ],
        "response_format": {
            "type": "json_schema",
            "json_schema": {
                "name": "sast_finding_review",
                "strict": True,
                "schema": _schema(),
            },
        },
    }
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(url, headers=headers, json=body)
    except httpx.TimeoutException as error:
        raise CodeScanningAiReviewError("AI provider timed out.") from error
    except httpx.HTTPError as error:
        raise CodeScanningAiReviewError("AI provider request failed.") from error

    if response.status_code in {401, 403}:
        raise CodeScanningAiReviewError("AI API key was rejected by the provider.")
    if response.status_code == 429:
        raise CodeScanningAiReviewError("AI provider rate limit reached. Try again later.")
    if response.status_code >= 400:
        raise CodeScanningAiReviewError(f"AI provider returned HTTP {response.status_code}.")

    try:
        provider_payload = response.json()
        choices = provider_payload.get("choices") or []
        if not choices:
            raise CodeScanningAiReviewError("AI provider returned no choices.")
        output_text = choices[0].get("message", {}).get("content")
        if not output_text:
            raise CodeScanningAiReviewError("AI provider returned an empty response.")
        assessment_payload = json.loads(output_text)
    except (ValueError, TypeError, KeyError) as error:
        raise CodeScanningAiReviewError("AI provider returned malformed output.") from error

    if not isinstance(assessment_payload, dict):
        raise CodeScanningAiReviewError("AI provider returned an unsupported output shape.")
    return _validate_review(assessment_payload)


async def review_code_scanning_finding(
    finding: dict[str, Any],
    sast_config: dict[str, Any],
) -> dict[str, Any]:
    """Review a SAST finding using the configured AI API.

    Returns a dict with keys: reasoning, verdict, explanation, confidence.
    Low-severity findings are skipped (no API call).
    Raises CodeScanningAiReviewError on failure.
    """
    tier = _get_tier(finding)
    if tier == "skip":
        return {
            "reasoning": "",
            "verdict": "skipped",
            "explanation": "Low severity finding — skipped by AI review tier policy.",
            "confidence": "low",
        }

    api_key = str(sast_config.get("aiApiKey") or "").strip()
    base_url = str(sast_config.get("aiBaseUrl") or "https://api.openai.com/v1").strip()
    model = str(sast_config.get("aiModelName") or "gpt-4o-mini").strip()

    if not api_key:
        raise CodeScanningAiReviewError("AI API key is not configured.")

    return await _request_ai_review(
        api_key=api_key,
        base_url=base_url,
        model=model,
        finding=finding,
        tier=tier,
    )
