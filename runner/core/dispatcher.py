"""Scanner dispatcher: maps backend job["type"] to an embedded scanner instance.

Replaces the Docker-per-scan execution model with in-process Python scanner
modules. The mapping keys are the exact strings the backend sends in job["type"]
(see backend src/scans/service.py::_SCANNER_JOB_TYPES)."""
from __future__ import annotations

from runner.scanners.agent.scanner import AgentScanner
from runner.scanners.code_scanning.scanner import CodeScanningScanner
from runner.scanners.container.scanner import ContainerScanner
from runner.scanners.deep_audit.scanner import DeepAuditScanner
from runner.scanners.dependencies.scanner import DependenciesScanner
from runner.scanners.deps_reachability.scanner import DepsReachabilityScanner
from runner.scanners.iac.scanner import IacScanner
from runner.scanners.secrets.scanner import SecretsScanner

_SCANNERS: dict[str, object] = {
    "dependencies_scanning": DependenciesScanner(),
    "container_scanning": ContainerScanner(),
    "secret_scanning": SecretsScanner(),
    "code_scanning": CodeScanningScanner(),
    "iac_scanning": IacScanner(),
    "agent_scanning": AgentScanner(),
    "deep_audit": DeepAuditScanner(),
    "dependencies_reachability": DepsReachabilityScanner(),
}


def get_scanner(scanner_type: str) -> object:
    if scanner_type not in _SCANNERS:
        raise ValueError(
            f"Unknown scanner type: {scanner_type!r}. "
            f"Supported: {sorted(_SCANNERS.keys())}"
        )
    return _SCANNERS[scanner_type]


def supported_types() -> list[str]:
    return list(_SCANNERS.keys())
