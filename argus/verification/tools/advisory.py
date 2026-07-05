"""Tool that fetches advisory text on demand for agents."""
from __future__ import annotations

import json
from typing import Any

from argus.verification.advisory_enrichment import fetch_advisory_details
from argus.verification.tools.base import Tool


def make_fetch_advisory_tool() -> Tool:
    def handler(args: dict[str, Any]) -> str:
        advisory_id = (args.get("advisory_id") or "").strip()
        if not advisory_id:
            return "// advisory_id is required"
        details = fetch_advisory_details([advisory_id])
        detail = details.get(advisory_id)
        if detail is None:
            return f"// no advisory found for {advisory_id}"
        return json.dumps(detail.to_dict(), indent=2, default=str)

    return Tool(
        name="fetch_advisory",
        description=(
            "Fetch full advisory text for a CVE or GHSA id from NVD + OSV.dev. "
            "Returns JSON with summary, long description, references, CWEs, "
            "vulnerable version range. Cached. Read-only."
        ),
        parameters={
            "type": "object",
            "properties": {
                "advisory_id": {
                    "type": "string",
                    "description": "A CVE id (CVE-YYYY-NNNNN) or GHSA id (GHSA-xxxx-xxxx-xxxx).",
                }
            },
            "required": ["advisory_id"],
        },
        handler=handler,
    )
