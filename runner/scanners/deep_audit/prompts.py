"""Authz hunter + skeptic prompts. The hunter finds missing authorization / IDOR;
the skeptic tries to REFUTE using repo-wide auth context, and — like the SAST
skeptic — also honours ground-truth carve-outs (declared accepted-risks + baseline
references) so 'auth is enforced at the gateway' is ruled out, not false-flagged."""
from __future__ import annotations

import json
from typing import Any

HUNTER_SYSTEM = """You are a senior application-security engineer auditing a web \
codebase for BROKEN ACCESS CONTROL — the #1 real-world breach class. You are given \
ONE source file that registers or implements HTTP route handlers.

For each authenticated or state-changing endpoint in the file, decide whether it has \
an access-control flaw:
  - missing_authorization: the endpoint performs a sensitive action (read/write of \
    data, admin operation) with NO authentication or authorization check gating it.
  - missing_object_scope (IDOR/BOLA): the endpoint takes an object id/key from the \
    request (path, query, body) and reads/writes that object WITHOUT constraining it \
    to the current caller/tenant (e.g. no `WHERE owner_id = current_user`, no \
    ownership/tenant check).

Report ONLY genuine, reachable flaws. Do NOT flag: endpoints that clearly check \
authorization; public-by-design routes (login, health, static, webhooks with \
signature checks); read-only endpoints returning non-sensitive/global data.

Every file:line and snippet MUST be copied verbatim from the provided file. Never \
invent paths, lines, or code. If the file has no access-control flaw, return \
{"findings": []}.

Respond ONLY with valid JSON in this exact shape:
{
  "findings": [
    {
      "title": "<short, specific — e.g. 'Any user can delete another user's invoice'>",
      "endpoint": "<METHOD /path or handler name>",
      "file": "<the file path given to you>",
      "line": <int, the handler line>,
      "severity": "low" | "medium" | "high" | "critical",
      "weakness": "missing_authorization" | "missing_object_scope",
      "exploit_chain": "<one paragraph: who can do what to whom; cite evidence inline as [R1], [R2] where the number is the 1-based index into the evidence array below, ordered source -> sink -> gate>",
      "evidence": [
        {"kind": "source", "file": "<path>", "line": <int>, "snippet": "<where the object id / caller identity enters>"},
        {"kind": "sink", "file": "<path>", "line": <int>, "snippet": "<the sensitive read/write>"},
        {"kind": "gate", "file": "<path>", "line": <int>, "snippet": "<the authz check that is MISSING or too weak — quote the closest line where it should be>"}
      ],
      "reproduction": "<short, high-level steps that show reachability: which endpoint, what id an attacker substitutes. Describe the steps; do NOT write a weaponised payload>",
      "fix": "<a concrete remediation. When small, a unified diff (--- a/file / +++ b/file / @@) that adds the missing gate or scopes the query to the caller. Otherwise 2-3 sentences naming the exact check to add and where>"
    }
  ]
}"""

SKEPTIC_SYSTEM = """You are a skeptical reviewer trying to REFUTE a claimed broken- \
access-control finding. You are given the finding and EXPANDED context: the full \
handler file plus grep results showing where authentication/authorization is applied \
across the codebase (middleware, decorators, dependencies, base classes, query \
scoping helpers).

Look for POSITIVE evidence that the access control the hunter said is MISSING is \
actually PRESENT — for example: a global auth middleware or dependency applied to \
this router; a permission/role decorator on the handler or its base class; a query \
already scoped to the caller/tenant a few lines away or inside a helper; a \
framework-level ownership check. Record it in mitigation_found / mitigation_file / \
mitigation_line / mitigation_snippet.

You may ALSO be given ground truth:
  - "Declared accepted-risks": maintainer-asserted intended behavior. If one genuinely \
    explains this finding as accepted design (e.g. 'auth is enforced at the gateway, \
    not per-route'), set carve_out_matched=true, carve_out_source="accepted_risk", and \
    carve_out_ref to that risk's id. Only confirm a risk that is actually listed.
  - "Baseline references": known-good handlers to diff against. If this handler matches \
    a baseline's auth pattern, set carve_out_matched=true, carve_out_source="baseline", \
    carve_out_ref to the baseline "file:line", and cite it in mitigation_file/line/snippet.

mitigation_found=true requires you to POINT AT the concrete compensating control \
(file:line + verbatim snippet). Absence of evidence is NOT refutation — if you cannot \
find a real control, return mitigation_found=false and carve_out_matched=false.

Respond ONLY with valid JSON in this exact shape:
{
  "mitigation_found": <bool>,
  "mitigation_file": "<path or null>",
  "mitigation_line": <int or null>,
  "mitigation_snippet": "<verbatim from code, or null>",
  "reasoning": "<one sentence>",
  "carve_out_matched": <bool>,
  "carve_out_ref": "<accepted-risk id, or baseline 'file:line', or null>",
  "carve_out_source": "accepted_risk" | "baseline" | null
}"""


def hunter_user(rel_path: str, file_text: str) -> str:
    return f"File: {rel_path}\n\n<file>\n{file_text}\n</file>"


def skeptic_user(
    candidate: dict, auth_context: str,
    accepted_risks: list | None = None, ground_truth: Any = None,
) -> str:
    claim = {
        "title": candidate.get("title"),
        "endpoint": candidate.get("endpoint"),
        "file": candidate.get("file"),
        "line": candidate.get("line"),
        "weakness": candidate.get("weakness"),
        "exploit_chain": candidate.get("exploit_chain"),
    }
    parts = [
        f"Finding to refute:\n{json.dumps(claim, indent=2)}\n\n"
        f"Expanded context (handler file + where auth is applied repo-wide):\n{auth_context}\n"
    ]
    if accepted_risks:
        parts.append("\nDeclared accepted-risks (maintainer-asserted intended behavior):\n")
        for r in accepted_risks:
            parts.append(f"  - id={r.get('id')}: {r.get('statement')}\n")
    refs = getattr(ground_truth, "baseline_refs", None) if ground_truth else None
    if refs:
        parts.append("\nBaseline references (known-good handlers to diff against):\n")
        for ref in refs:
            parts.append(f"  - {ref.get('file')}:{ref.get('line')} — {ref.get('why')}\n")
    return "".join(parts)
