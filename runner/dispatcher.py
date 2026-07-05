"""Scanner dispatcher: maps backend job["type"] to an embedded scanner instance.

Replaces the Docker-per-scan execution model with in-process Python scanner
modules. The mapping keys are the exact strings the backend sends in job["type"],
which is why "code-scanning" uses a hyphen (the Python package uses underscore)."""
from __future__ import annotations

from runner.scanners.base import BaseScanner
from runner.scanners.code_scanning.scanner import CodeScanningScanner
from runner.scanners.container.scanner import ContainerScanner
from runner.scanners.dependencies.scanner import DependenciesScanner
from runner.scanners.secrets.scanner import SecretsScanner

_SCANNERS: dict[str, BaseScanner] = {
    "dependencies": DependenciesScanner(),
    "container": ContainerScanner(),
    "secrets": SecretsScanner(),
    "code-scanning": CodeScanningScanner(),
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
