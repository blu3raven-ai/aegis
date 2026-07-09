"""Lens 1 — Broken Access Control (missing authorization + IDOR/BOLA).

The class semgrep structurally can't find: a handler that performs a sensitive
read/write without checking that the caller is allowed to act on that specific
object. Two weaknesses:
  - missing_authorization: no permission/role/auth check gates the endpoint.
  - missing_object_scope: the object id comes from the request and the query
    isn't scoped to the caller (IDOR/BOLA).
"""
from __future__ import annotations

import json

from runner.scanners.deep_audit.lenses.base import Lens, register
from runner.scanners.deep_audit.schemas import AuditFinding

_HUNTER_SYSTEM = """You are a senior application-security engineer auditing a web \
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
      "title": "<short, specific — e.g. 'Any user can delete another user\\'s invoice'>",
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

_SKEPTIC_SYSTEM = """You are a skeptical reviewer trying to REFUTE a claimed broken- \
access-control finding. You are given the finding and EXPANDED context: the full \
handler file plus grep results showing where authentication/authorization is applied \
across the codebase (middleware, decorators, dependencies, base classes, query \
scoping helpers).

Look for POSITIVE evidence that the access control the hunter said is MISSING is \
actually PRESENT — for example: a global auth middleware or dependency applied to \
this router; a permission/role decorator on the handler or its base class; a query \
that is already scoped to the caller/tenant a few lines away or inside a helper; a \
framework-level ownership check.

refuted=true requires you to POINT AT the concrete compensating control (file:line + \
snippet). Absence of evidence is NOT refutation — if you cannot find a real control, \
return refuted=false. If the control exists but is clearly wrong for this object \
(e.g. checks a different resource), return refuted=false.

Respond ONLY with valid JSON:
{
  "refuted": true | false,
  "reason": "<one sentence>",
  "compensating_control": "<file:line + verbatim snippet of the control you found, or empty>"
}"""


def _hunter_user(rel_path: str, file_text: str) -> str:
    return f"File: {rel_path}\n\n<file>\n{file_text}\n</file>"


def _skeptic_user(finding: AuditFinding, context: str) -> str:
    claim = {
        "title": finding.title,
        "endpoint": finding.endpoint,
        "file": finding.file,
        "line": finding.line,
        "weakness": finding.weakness,
        "exploit_chain": finding.exploit_chain,
    }
    return (
        f"Finding to refute:\n{json.dumps(claim, indent=2)}\n\n"
        f"Expanded context (handler file + where auth is applied repo-wide):\n{context}"
    )


AUTHZ_LENS = register(Lens(
    key="authz",
    category="Broken Access Control",
    default_cwe="CWE-284",
    owasp="A01:2021 Broken Access Control",
    path_keywords=(
        "route", "router", "controller", "handler", "endpoint", "/api/", "/views",
        "urls.py", "routes.rb", "/resolvers",
    ),
    route_markers=(
        "@app.", "@router.", "app.get(", "app.post(", "app.put(", "app.delete(",
        "router.get(", "router.post(", "@RestController", "@GetMapping", "@PostMapping",
        "@RequestMapping", "def create", "def update", "def destroy", "path(", "resources ",
        "@strawberry.field", "@Get(", "@Post(", "http.HandleFunc",
    ),
    hunter_system=_HUNTER_SYSTEM,
    skeptic_system=_SKEPTIC_SYSTEM,
    weakness_cwe={
        "missing_authorization": "CWE-862",
        "missing_object_scope": "CWE-639",
    },
    hunter_user=_hunter_user,
    skeptic_user=_skeptic_user,
))
