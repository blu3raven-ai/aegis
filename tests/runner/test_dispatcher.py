"""Tests for runner.core.dispatcher — scanner type → scanner instance routing."""
import pytest

from runner.core.dispatcher import get_scanner, supported_types
from runner.scanners.dependencies.scanner import DependenciesScanner
from runner.scanners.container.scanner import ContainerScanner
from runner.scanners.secrets.scanner import SecretsScanner
from runner.scanners.code_scanning.scanner import CodeScanningScanner


@pytest.mark.parametrize("scanner_type,expected_cls", [
    ("dependencies_scanning", DependenciesScanner),
    ("container_scanning", ContainerScanner),
    ("secret_scanning", SecretsScanner),
    ("code_scanning", CodeScanningScanner),
])
def test_get_scanner_returns_correct_instance(scanner_type, expected_cls):
    scanner = get_scanner(scanner_type)
    assert isinstance(scanner, expected_cls)


def test_get_scanner_raises_on_unknown_type():
    with pytest.raises(ValueError, match="Unknown scanner type"):
        get_scanner("rocket-launcher")


def test_get_scanner_returns_same_instance():
    """Scanners are singletons — dispatcher returns the same instance each time."""
    a = get_scanner("dependencies_scanning")
    b = get_scanner("dependencies_scanning")
    assert a is b


def test_supported_types_lists_all_scanners():
    types = supported_types()
    assert set(types) == {
        "dependencies_scanning",
        "container_scanning",
        "secret_scanning",
        "code_scanning",
        "deep_audit",
        "iac_scanning",
        "agent_scanning",
        "dependencies_reachability",
        "container_verification",
    }
