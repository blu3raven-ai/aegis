"""Scanner dispatcher: maps backend job["type"] to an embedded scanner instance.

Replaces the Docker-per-scan execution model with in-process Python scanner
modules. The mapping keys are the exact strings the backend sends in job["type"]
(see backend src/scans/service.py::_SCANNER_JOB_TYPES)."""
from __future__ import annotations

from runner.scanners.base import BaseScanner
from runner.scanners.code_scanning.scanner import CodeScanningScanner
from runner.scanners.container.scanner import ContainerScanner
from runner.scanners.dependencies.scanner import DependenciesScanner
from runner.scanners.iac.scanner import IacScanner
from runner.scanners.secrets.scanner import SecretsScanner
from runner.scanners.verification.scanner import VerificationScanner

_SCANNERS: dict[str, BaseScanner] = {
    "dependencies_scanning": DependenciesScanner(),
    "container_scanning": ContainerScanner(),
    "secret_scanning": SecretsScanner(),
    "code_scanning": CodeScanningScanner(),
    "iac_scanning": IacScanner(),
    "verification": VerificationScanner(),
}


def get_scanner(scanner_type: str) -> BaseScanner:
    if scanner_type not in _SCANNERS:
        raise ValueError(
            f"Unknown scanner type: {scanner_type!r}. "
            f"Supported: {sorted(_SCANNERS.keys())}"
        )
    return _SCANNERS[scanner_type]


def supported_types() -> list[str]:
    return list(_SCANNERS.keys())
