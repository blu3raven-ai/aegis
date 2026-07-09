"""Audit lenses. Importing this package registers every lens with the engine —
add a new lens module here and it becomes selectable via DEEP_AUDIT_LENSES."""
from runner.scanners.deep_audit.lenses import authz as _authz  # noqa: F401

__all__ = ["_authz"]
