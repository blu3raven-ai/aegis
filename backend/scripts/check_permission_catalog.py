#!/usr/bin/env python3
"""Fail if any permission check uses a raw string literal.

Every require_permission / has_permission / has_role_permission call site
must reference a constant from src.authz.permissions.catalog. The catalog
file itself is exempt.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1] / "src"
ALLOWED_FILES = {
    ROOT / "authz" / "permissions" / "catalog.py",
}
PATTERN = re.compile(
    r'(require_permission|has_permission|has_role_permission)\s*\(\s*[^,]+,\s*"[a-z_]+"'
)


def main() -> int:
    offenders: list[str] = []
    for path in ROOT.rglob("*.py"):
        if path in ALLOWED_FILES:
            continue
        for lineno, line in enumerate(path.read_text().splitlines(), start=1):
            if PATTERN.search(line):
                offenders.append(f"{path.relative_to(ROOT.parent)}:{lineno}: {line.strip()}")

    if offenders:
        sys.stderr.write(
            "Raw permission strings found. Import the constant from "
            "src.authz.permissions.catalog instead.\n\n"
        )
        for entry in offenders:
            sys.stderr.write(entry + "\n")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
