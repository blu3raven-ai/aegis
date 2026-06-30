"""Deterministic IaC config-hardening patches for checkov misconfigurations.

For checkov findings whose corrective change is pattern-clear (set a hardening
flag, add an encryption block), this module emits a structured
``recommended_fix`` of ``kind="config_patch"`` carrying a verbatim ``before``
block and a corrected ``after`` block. There is no LLM involved: the transform
is a fixed template keyed on the checkov ``check_id``. It runs for any IaC
finding with a mapped check_id, independent of severity or the optional LLM
verifier.

Each generated patch is re-validated by running checkov on the patched block in
isolation; ``validated`` reflects that re-scan honestly (and is ``False`` when
checkov is unavailable or the block won't parse). The patch is a SUGGESTION
only — no file in the repo working tree is modified; the re-scan uses a
throwaway temp file that is cleaned up.
"""
from __future__ import annotations

import json
import logging
import os
import re
import shutil
import tempfile
from collections import defaultdict
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from runner.scanners._subprocess import ScannerTimeoutError, run_tool

logger = logging.getLogger(__name__)

_RECHECK_TIMEOUT: float = 120.0

# IaC files this module knows how to read/patch. Anything else is left alone.
_TERRAFORM_EXTS = (".tf", ".hcl")
_YAML_EXTS = (".yaml", ".yml")


# ---------------------------------------------------------------------------
# Checkov re-scan (single file)
# ---------------------------------------------------------------------------


def _run_checkov_on_text(block: str, ext: str) -> dict | list | None:
    """Run checkov on ``block`` written to a throwaway temp file.

    Mirrors the scanner's ``_run_checkov`` shell-out but scopes to a single file
    via ``-f``. Returns the parsed checkov JSON (dict or per-framework list), or
    ``None`` when checkov is unavailable, times out, errors, or emits
    unparseable output. Never raises — re-validation must not break a scan.
    """
    if shutil.which("checkov") is None:
        return None

    tmp_dir = tempfile.mkdtemp(prefix="iac_recheck_")
    try:
        # checkov picks the framework from the file extension, so preserve it.
        tmp_file = Path(tmp_dir) / f"resource{ext or '.tf'}"
        tmp_file.write_text(block, encoding="utf-8")
        rc, stdout, _ = run_tool(
            [
                "checkov",
                "-f",
                str(tmp_file),
                "-o",
                "json",
                "--quiet",
                "--skip-download",
            ],
            timeout=_RECHECK_TIMEOUT,
        )
        # Checkov convention: 0 = clean, 1 = findings present, other = error.
        if rc not in (0, 1):
            return None
        return json.loads(stdout or "{}")
    except (ScannerTimeoutError, json.JSONDecodeError, OSError):
        return None
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


def _summarize_checkov(raw: dict | list) -> tuple[bool, frozenset[str]]:
    """Return ``(parsed_ok, failed_check_ids)`` from a checkov JSON payload."""
    blocks = raw if isinstance(raw, list) else [raw]
    failed: set[str] = set()
    parse_errors = 0
    saw_results = False
    for block in blocks:
        if not isinstance(block, dict):
            continue
        results = block.get("results") or {}
        saw_results = True
        for chk in results.get("failed_checks") or []:
            cid = chk.get("check_id")
            if cid:
                failed.add(cid)
        parse_errors += int((block.get("summary") or {}).get("parsing_errors") or 0)
    return (saw_results and parse_errors == 0), frozenset(failed)


def recheck_iac(
    patched_block: str,
    check_id: str,
    repo_root: str,
    *,
    ext: str = ".tf",
    baseline_check_ids: frozenset[str] = frozenset(),
) -> bool:
    """Re-run checkov on a patched block and report whether it cleanly fixes it.

    Returns ``True`` only when, on the isolated patched block, checkov parsed the
    file (no parse error), the original ``check_id`` no longer fails, and no
    *new* check fired — i.e. every check still failing was already failing on the
    original resource (``baseline_check_ids``). Returns ``False`` — never raises —
    when checkov is unavailable or the block does not parse, so the fix can still
    be surfaced with ``validated=False``.

    ``repo_root`` is accepted for call-site symmetry with the other helpers; the
    re-scan runs against a temp file, never inside the repo tree.
    """
    raw = _run_checkov_on_text(patched_block, ext)
    if raw is None:
        return False
    parsed_ok, failed = _summarize_checkov(raw)
    if not parsed_ok:
        return False
    if check_id in failed:
        return False
    # No regression: the patch must not introduce a failing check that the
    # original resource did not already have.
    return failed <= set(baseline_check_ids)


# ---------------------------------------------------------------------------
# Verbatim block extraction (path-safe)
# ---------------------------------------------------------------------------


def _safe_read_lines(repo_root: str, file_path: str) -> list[str] | None:
    """Read ``file_path`` under ``repo_root`` and return its lines verbatim.

    Refuses anything that resolves outside ``repo_root`` (``../`` traversal or a
    symlink escaping the clone), mirroring the verifier's resource-excerpt guard.
    """
    try:
        root = Path(repo_root).resolve()
        full = (root / file_path).resolve()
    except OSError:
        return None
    if not full.is_relative_to(root) or not full.is_file():
        return None
    try:
        return full.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return None


def _extract_tf_block(lines: Sequence[str], start_line: int) -> str | None:
    """Extract a brace-balanced Terraform block starting at ``start_line`` (1-based)."""
    n = len(lines)
    i = start_line - 1
    if i < 0 or i >= n:
        return None
    depth = 0
    started = False
    out: list[str] = []
    for j in range(i, n):
        line = lines[j]
        out.append(line)
        for ch in line:
            if ch == "{":
                depth += 1
                started = True
            elif ch == "}":
                depth -= 1
        if started and depth <= 0:
            return "\n".join(out)
    return None  # unbalanced — fail closed rather than emit a partial block


def _extract_yaml_block(lines: Sequence[str], start_line: int) -> str | None:
    """Extract the YAML document containing ``start_line`` (1-based).

    K8s manifests carry one resource per ``---``-delimited document; checkov's
    line range points into that document. We slice between the surrounding
    separators so the block is a self-contained, re-scannable manifest.
    """
    n = len(lines)
    i = start_line - 1
    if i < 0 or i >= n:
        return None
    start = 0
    for j in range(i, -1, -1):
        if lines[j].strip() == "---":
            start = j + 1
            break
    end = n
    for j in range(i + 1, n):
        if lines[j].strip() == "---":
            end = j
            break
    block = "\n".join(lines[start:end]).strip("\n")
    return block or None


# ---------------------------------------------------------------------------
# Terraform transforms
# ---------------------------------------------------------------------------


def _tf_indent_close(lines: list[str], snippet: list[str]) -> str | None:
    """Insert ``snippet`` immediately before the block's closing brace."""
    for idx in range(len(lines) - 1, -1, -1):
        if lines[idx].strip() == "}":
            return "\n".join(lines[:idx] + snippet + lines[idx:])
    return None


def _tf_set_bool(attr: str) -> Callable[[str], str | None]:
    """Build a transform that sets a boolean ``attr`` to ``true`` on a TF block.

    Flips a literal ``false`` to ``true`` (or inserts ``attr = true`` when the
    attribute is absent and therefore defaults insecure). Returns ``None`` when
    the attribute is bound to a non-literal (a variable / expression) — that is
    not a pattern-clear fix, so we refuse to guess.
    """

    pattern = re.compile(r"^(\s*)" + re.escape(attr) + r"(\s*=\s*)(.+?)\s*$")

    def _transform(before: str) -> str | None:
        lines = before.split("\n")
        for idx, line in enumerate(lines):
            match = pattern.match(line)
            if match:
                current = match.group(3).strip()
                if current == "true":
                    return None  # already hardened — no patch needed
                if current != "false":
                    return None  # non-literal value — don't guess
                lines[idx] = f"{match.group(1)}{attr}{match.group(2)}true"
                return "\n".join(lines)
        base_indent = re.match(r"^(\s*)", lines[0]).group(1)
        return _tf_indent_close(lines, [f"{base_indent}  {attr} = true"])

    return _transform


_SSE_SNIPPET = (
    "server_side_encryption_configuration {",
    "  rule {",
    "    apply_server_side_encryption_by_default {",
    '      sse_algorithm = "aws:kms"',
    "    }",
    "  }",
    "}",
)


def _tf_add_sse(before: str) -> str | None:
    """Insert a KMS server-side-encryption block into an S3 bucket resource."""
    if "server_side_encryption_configuration" in before:
        return None  # already present — finding would not fire
    lines = before.split("\n")
    base_indent = re.match(r"^(\s*)", lines[0]).group(1)
    body_indent = base_indent + "  "
    snippet = [f"{body_indent}{s}" if s else s for s in _SSE_SNIPPET]
    return _tf_indent_close(lines, snippet)


# ---------------------------------------------------------------------------
# Kubernetes (YAML) transforms
# ---------------------------------------------------------------------------


def _find_container_lists(node: Any) -> list[list]:
    """Recursively collect every ``containers`` / ``initContainers`` list."""
    found: list[list] = []
    if isinstance(node, dict):
        for key, value in node.items():
            if key in ("containers", "initContainers") and isinstance(value, list):
                found.append(value)
            else:
                found.extend(_find_container_lists(value))
    elif isinstance(node, list):
        for item in node:
            found.extend(_find_container_lists(item))
    return found


def _yaml_set_security_context(key: str, value: bool) -> Callable[[str], str | None]:
    """Build a transform that sets ``securityContext.<key>`` on every container.

    Uses a YAML round-trip so the result is guaranteed well-formed. Returns
    ``None`` when the block carries no container list (nothing pattern-clear to
    patch) or YAML/ruamel is unavailable.
    """

    def _transform(before: str) -> str | None:
        try:
            from io import StringIO

            from ruamel.yaml import YAML
            from ruamel.yaml.comments import CommentedMap
        except ImportError:
            return None

        yaml = YAML()
        yaml.preserve_quotes = True
        try:
            data = yaml.load(before)
        except Exception:  # noqa: BLE001 — malformed YAML: refuse to patch
            return None
        if data is None:
            return None

        container_lists = _find_container_lists(data)
        if not container_lists:
            return None

        touched = False
        for containers in container_lists:
            for container in containers:
                if not isinstance(container, dict):
                    continue
                sec = container.get("securityContext")
                if sec is None:
                    sec = CommentedMap()
                    container["securityContext"] = sec
                sec[key] = value
                touched = True
        if not touched:
            return None

        buf = StringIO()
        yaml.dump(data, buf)
        return buf.getvalue().strip("\n")

    return _transform


# ---------------------------------------------------------------------------
# Template catalog
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _Template:
    """A deterministic patch template for one checkov ``check_id``."""

    title: str
    rationale: str  # may contain a ``{check_id}`` placeholder
    file_kind: str  # "terraform" | "yaml"
    transform: Callable[[str], str | None]


CHECK_ID_TEMPLATES: dict[str, _Template] = {
    # S3 encryption at rest — add a KMS server-side-encryption block.
    "CKV_AWS_19": _Template(
        title="Enable server-side encryption on the S3 bucket",
        rationale=(
            "checkov {check_id} flags the bucket as unencrypted at rest; a "
            "server_side_encryption_configuration with aws:kms encrypts stored "
            "objects."
        ),
        file_kind="terraform",
        transform=_tf_add_sse,
    ),
    "CKV_AWS_145": _Template(
        title="Encrypt the S3 bucket with KMS",
        rationale=(
            "checkov {check_id} requires KMS encryption at rest; the added "
            "server_side_encryption_configuration sets sse_algorithm to aws:kms."
        ),
        file_kind="terraform",
        transform=_tf_add_sse,
    ),
    # S3 public access block — set each guard flag to true.
    "CKV_AWS_53": _Template(
        title="Block public ACLs on the S3 bucket",
        rationale="checkov {check_id}: block_public_acls must be true.",
        file_kind="terraform",
        transform=_tf_set_bool("block_public_acls"),
    ),
    "CKV_AWS_54": _Template(
        title="Block public bucket policies on the S3 bucket",
        rationale="checkov {check_id}: block_public_policy must be true.",
        file_kind="terraform",
        transform=_tf_set_bool("block_public_policy"),
    ),
    "CKV_AWS_55": _Template(
        title="Ignore public ACLs on the S3 bucket",
        rationale="checkov {check_id}: ignore_public_acls must be true.",
        file_kind="terraform",
        transform=_tf_set_bool("ignore_public_acls"),
    ),
    "CKV_AWS_56": _Template(
        title="Restrict public bucket access on the S3 bucket",
        rationale="checkov {check_id}: restrict_public_buckets must be true.",
        file_kind="terraform",
        transform=_tf_set_bool("restrict_public_buckets"),
    ),
    # Kubernetes container hardening — set the securityContext flag.
    "CKV_K8S_16": _Template(
        title="Drop privileged mode on the container",
        rationale=(
            "checkov {check_id}: containers must not run privileged; "
            "securityContext.privileged is set to false."
        ),
        file_kind="yaml",
        transform=_yaml_set_security_context("privileged", False),
    ),
    "CKV_K8S_20": _Template(
        title="Disable privilege escalation on the container",
        rationale=(
            "checkov {check_id}: securityContext.allowPrivilegeEscalation is set "
            "to false."
        ),
        file_kind="yaml",
        transform=_yaml_set_security_context("allowPrivilegeEscalation", False),
    ),
    "CKV_K8S_22": _Template(
        title="Make the container root filesystem read-only",
        rationale=(
            "checkov {check_id}: securityContext.readOnlyRootFilesystem is set "
            "to true."
        ),
        file_kind="yaml",
        transform=_yaml_set_security_context("readOnlyRootFilesystem", True),
    ),
    "CKV_K8S_23": _Template(
        title="Run the container as a non-root user",
        rationale=(
            "checkov {check_id}: securityContext.runAsNonRoot is set to true."
        ),
        file_kind="yaml",
        transform=_yaml_set_security_context("runAsNonRoot", True),
    ),
}

# Pattern-clear checks deliberately left UNMAPPED because their corrective value
# is caller-intent-dependent (a trusted CIDR, a least-privilege action set, a
# target log bucket) or requires synthesizing a whole sibling resource — neither
# is a deterministic literal we can choose without guessing. Candidates for a
# later (LLM-assisted or context-aware) pass, not for the deterministic path:
#   CKV2_AWS_6              S3 bucket missing a public-access-block resource
#   CKV_AWS_18             S3 access logging (needs a target log bucket)
#   CKV_AWS_24/25/260      security-group ingress from 0.0.0.0/0 (trusted CIDR)
#   CKV_AWS_1/62/111/290   over-permissive IAM wildcards (least-privilege scope)
#   CKV_AWS_103            load balancer TLS policy (protocol/policy/cert ARN)
_CONTEXT_DEPENDENT_CHECKS: tuple[str, ...] = (
    "CKV2_AWS_6",
    "CKV_AWS_18",
    "CKV_AWS_24",
    "CKV_AWS_25",
    "CKV_AWS_260",
    "CKV_AWS_1",
    "CKV_AWS_62",
    "CKV_AWS_111",
    "CKV_AWS_290",
    "CKV_AWS_103",
)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def _block_for(finding: dict[str, Any], repo_root: str, file_kind: str) -> str | None:
    file_path = finding.get("file") or ""
    line = int(finding.get("line") or 1)
    lines = _safe_read_lines(repo_root, file_path)
    if lines is None:
        return None
    if file_kind == "terraform":
        return _extract_tf_block(lines, line)
    return _extract_yaml_block(lines, line)


def build_iac_fix(
    finding: dict[str, Any],
    repo_root: str,
    *,
    baseline_check_ids: frozenset[str] = frozenset(),
) -> dict[str, Any] | None:
    """Build a deterministic ``config_patch`` recommended_fix for one finding.

    Returns ``None`` when the ``check_id`` is unmapped (never a guessed fix),
    when the resource block can't be read/extracted, or when the template can't
    cleanly apply. Otherwise returns the structured fix; ``validated`` reflects a
    checkov re-scan of the patched block.

    ``baseline_check_ids`` is the set of checks the original scan reported for
    this resource — passed by :func:`attach_iac_fixes` so a multi-check resource
    (e.g. the four S3 public-access-block flags) isn't judged as regressed when
    its sibling checks remain. The repo working tree is never modified.
    """
    check_id = (finding.get("check_id") or "").strip()
    template = CHECK_ID_TEMPLATES.get(check_id)
    if template is None:
        return None

    before = _block_for(finding, repo_root, template.file_kind)
    if not before:
        return None

    after = template.transform(before)
    if not after or after == before:
        return None

    file_path = finding.get("file") or ""
    ext = os.path.splitext(file_path)[1].lower()
    if not ext:
        ext = ".tf" if template.file_kind == "terraform" else ".yaml"

    baseline = baseline_check_ids or frozenset({check_id})
    validated = recheck_iac(
        after, check_id, repo_root, ext=ext, baseline_check_ids=baseline
    )

    return {
        "kind": "config_patch",
        "source": "deterministic",
        "title": template.title,
        "rationale": template.rationale.format(check_id=check_id),
        "filePath": file_path,
        "resource": finding.get("resource") or "",
        "before": before,
        "after": after,
        "validated": validated,
    }


def attach_iac_fixes(
    findings: list[dict[str, Any]], repo_root: str
) -> list[dict[str, Any]]:
    """Attach a deterministic ``recommended_fix`` to every mapped IaC finding.

    Always-on and decoupled from the LLM verifier: runs for any finding whose
    ``check_id`` has a template, regardless of severity or verdict. Mutates and
    returns ``findings``. Per-finding failures are logged and skipped so
    remediation can never break a scan.
    """
    groups: dict[tuple[Any, Any], set[str]] = defaultdict(set)
    for finding in findings:
        key = (finding.get("file"), finding.get("resource"))
        cid = (finding.get("check_id") or "").strip()
        if cid:
            groups[key].add(cid)

    for finding in findings:
        key = (finding.get("file"), finding.get("resource"))
        baseline = frozenset(groups.get(key, set()))
        try:
            fix = build_iac_fix(finding, repo_root, baseline_check_ids=baseline)
        except Exception:  # noqa: BLE001 — remediation must not break the scan
            logger.exception(
                "[!] iac remediation failed for %s", finding.get("check_id")
            )
            fix = None
        if fix:
            finding["recommended_fix"] = fix
    return findings
