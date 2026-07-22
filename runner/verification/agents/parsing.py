"""Extract a JSON object from prose-wrapped agent output."""
from __future__ import annotations

import json


def extract_json_object(text: str) -> dict | None:
    """Return the first JSON object found in ``text``, or None.

    Agent final messages may wrap the JSON in prose or code fences, so try the
    whole stripped string first, then the widest brace span.
    """
    if not text:
        return None
    candidates: list[str] = []
    stripped = text.strip()
    if stripped.startswith("{") and stripped.endswith("}"):
        candidates.append(stripped)
    start = text.find("{")
    end = text.rfind("}")
    if 0 <= start < end:
        candidates.append(text[start : end + 1])
    for c in candidates:
        try:
            obj = json.loads(c)
            if isinstance(obj, dict):
                return obj
        except json.JSONDecodeError:
            continue
    return None
