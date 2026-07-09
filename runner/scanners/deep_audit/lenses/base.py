"""Lens abstraction for the deep-audit engine.

A *lens* is one class of reasoning-found vulnerability (broken access control
first; SSRF, business-logic, mass-assignment, etc. later). It supplies only what
is class-specific — which files to look at, and the hunter/skeptic prompts. The
engine, concurrency, budget, grounding, ingest, and UI are shared, so adding the
next lens is a new prompt, not a new scanner.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable

from runner.scanners.deep_audit.schemas import AuditFinding


@dataclass(frozen=True)
class Lens:
    key: str  # short id, e.g. "authz" — used in check_id and finding category
    category: str  # human label, e.g. "Broken Access Control"
    default_cwe: str  # e.g. "CWE-862"
    owasp: str  # e.g. "A01:2021 Broken Access Control"
    # A file is a candidate when its path contains one of these substrings OR its
    # content matches one of route_markers — a cheap pre-filter so non-handler
    # files never reach the model.
    path_keywords: tuple[str, ...]
    route_markers: tuple[str, ...]
    hunter_system: str
    skeptic_system: str
    # Map a finding's `weakness` to a more specific CWE; falls back to default_cwe.
    weakness_cwe: dict[str, str] = field(default_factory=dict)
    # Per-lens builders for the user turn (kept as callables so a lens can shape
    # its own context without the engine knowing lens internals).
    hunter_user: Callable[[str, str], str] = None  # (rel_path, file_text) -> str
    skeptic_user: Callable[[AuditFinding, str], str] = None  # (finding, context) -> str

    def cwe_for(self, weakness: str) -> str:
        return self.weakness_cwe.get(weakness, self.default_cwe)

    def check_id(self, weakness: str) -> str:
        """Stable rule id, e.g. AUTHZ_MISSING_AUTHORIZATION."""
        suffix = re.sub(r"[^A-Z0-9]+", "_", (weakness or "finding").upper()).strip("_")
        return f"{self.key.upper()}_{suffix or 'FINDING'}"

    def route_marker_re(self) -> re.Pattern:
        if not self.route_markers:
            return re.compile(r"$^")  # matches nothing
        return re.compile("|".join(re.escape(m) for m in self.route_markers))


# Registry — the engine iterates the lenses a scan requested. v1 ships authz.
_REGISTRY: dict[str, Lens] = {}


def register(lens: Lens) -> Lens:
    _REGISTRY[lens.key] = lens
    return lens


def get_lens(key: str) -> Lens | None:
    return _REGISTRY.get(key)


def all_lenses() -> list[Lens]:
    return list(_REGISTRY.values())
