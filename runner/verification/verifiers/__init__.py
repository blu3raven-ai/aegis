"""Per-scanner verify_<type>_finding orchestrations."""
from __future__ import annotations

from runner.verification.verifiers.deps import verify_deps_finding
from runner.verification.verifiers.iac import verify_iac_finding

__all__ = ("verify_deps_finding", "verify_iac_finding")
