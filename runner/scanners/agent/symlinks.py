"""Flag committed symlinks that escape the repo or point at sensitive targets.

The GhostApproval / SymJack class (CVE-2026-12958, CVE-2026-50549, and siblings):
a repo ships a symlink disguised as a benign file — e.g. ``project_settings.json``
that really points to ``~/.ssh/authorized_keys`` or ``~/.zshrc``. An agent asked to
"append to the settings file" lands the write on the real target, and the approval
box shows the harmless name, not the resolved path — an informed-consent bypass
enabling key-planting (code execution) or secret exfiltration. It is invisible in
``git status`` for the victim. Catch it at scan time, before the repo reaches an agent.
"""
from __future__ import annotations

import hashlib
import os

_SYMLINK_ESCAPE = "AGENT_SYMLINK_ESCAPE"
_GUIDELINE = "https://owasp.org/www-project-top-10-for-large-language-model-applications/"

# Match the other agent passes: never descend these.
_SKIP_DIRS = frozenset({".git", "node_modules", ".venv", "venv", "dist", "build", ".next"})

# Sensitive fragments a disguised symlink commonly targets → treat as critical.
_SENSITIVE = (
    ".ssh", "authorized_keys", "id_rsa", "id_ed25519", ".aws", "credentials",
    ".zshrc", ".bashrc", ".bash_profile", ".profile", ".gitconfig", ".npmrc",
    ".netrc", ".kube", ".docker/config", "/etc/", "shadow", "passwd",
)

_MAX = 50


def _finding(rel_path: str, target: str, sensitive: bool) -> dict:
    fp = hashlib.sha1(f"agent:{rel_path}:{_SYMLINK_ESCAPE}".encode()).hexdigest()[:16]
    reason = "points at a sensitive file outside the repo" if sensitive else "escapes the repository root"
    return {
        "check_id": _SYMLINK_ESCAPE,
        "title": f"Committed symlink {reason}: {rel_path}",
        "severity": "critical" if sensitive else "high",
        "file": rel_path,
        "line": 1,
        "resource": _SYMLINK_ESCAPE,
        "guideline": _GUIDELINE,
        "fingerprint": fp,
        "evidence": {"symlink": rel_path, "target": target[:200]},
    }


def _classify(raw_target: str, abs_path: str, root: str) -> str | None:
    """None → safe (in-repo). "sensitive"/"escape" → flag. Decided on the raw link
    text (attacker's intent) and the resolved destination (backstop)."""
    low = raw_target.lower()
    if any(s in low for s in _SENSITIVE):
        return "sensitive"
    escapes = raw_target.startswith(("/", "~")) or raw_target.startswith("..") or ".." in raw_target.split("/")
    resolved = os.path.realpath(abs_path)
    if not (resolved == root or resolved.startswith(root + os.sep)):
        escapes = True
    return "escape" if escapes else None


def scan_symlinks(repo_root: str) -> list[dict]:
    """Repo-wide pass: flag any committed symlink that resolves outside the repo."""
    root = os.path.realpath(repo_root)
    findings: list[dict] = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        for name in list(filenames) + list(dirnames):  # symlinked dirs are not descended, but still flagged
            abs_path = os.path.join(dirpath, name)
            if not os.path.islink(abs_path):
                continue
            try:
                raw = os.readlink(abs_path)
            except OSError:
                continue
            kind = _classify(raw, abs_path, root)
            if kind:
                findings.append(_finding(os.path.relpath(abs_path, root), raw, kind == "sensitive"))
                if len(findings) >= _MAX:
                    return findings
    return findings
