"""Rule registry — import all built-in rules and expose a factory.

To register all built-in rules on an engine:
    from src.correlation.rules import register_builtin_rules
    register_builtin_rules(engine)
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from src.correlation.rules.intel_match import IntelMatchRule
from src.correlation.rules.reachable_cve import ReachableCveRule
from src.correlation.rules.secret_to_resource import SecretToResourceRule
from src.correlation.rules.lifecycle import LifecycleRule
from src.correlation.rules.epss_escalation import EpssEscalationRule
from src.correlation.rules.public_exposure_data_handling import PublicExposureDataHandlingRule
from src.correlation.rules.cross_repo_cve_cluster import CrossRepoCveClusterRule
from src.correlation.rules.container_base_image_propagation import ContainerBaseImagePropagationRule
from src.correlation.rules.credential_reuse_chain import CredentialReuseChainRule
from src.correlation.rules.temporal import (
    AttributionRollupRule,
    SeverityVelocityRule,
    MttrTrackingRule,
    AnomalyDetectionRule,
)

if TYPE_CHECKING:
    from src.correlation.engine import CorrelationEngine

__all__ = [
    "IntelMatchRule",
    "ReachableCveRule",
    "SecretToResourceRule",
    "LifecycleRule",
    "EpssEscalationRule",
    "PublicExposureDataHandlingRule",
    "CrossRepoCveClusterRule",
    "ContainerBaseImagePropagationRule",
    "CredentialReuseChainRule",
    "AttributionRollupRule",
    "SeverityVelocityRule",
    "MttrTrackingRule",
    "AnomalyDetectionRule",
    "register_builtin_rules",
    "register_temporal_rules",
]


def register_builtin_rules(engine: "CorrelationEngine") -> None:
    """Register all thirteen built-in correlation rules on the given engine."""
    engine.register_rule(IntelMatchRule())
    engine.register_rule(ReachableCveRule())
    engine.register_rule(SecretToResourceRule())
    engine.register_rule(LifecycleRule())
    engine.register_rule(EpssEscalationRule())
    engine.register_rule(PublicExposureDataHandlingRule())
    engine.register_rule(CrossRepoCveClusterRule())
    engine.register_rule(ContainerBaseImagePropagationRule())
    engine.register_rule(CredentialReuseChainRule())
    register_temporal_rules(engine)


def register_temporal_rules(engine: "CorrelationEngine") -> None:
    """Register the four Phase 11 Type 4 temporal rules.

    Exposed as a standalone function so callers can opt-in selectively
    without pulling in the full builtin set (useful for isolated testing).
    """
    engine.register_rule(AttributionRollupRule())
    engine.register_rule(SeverityVelocityRule())
    engine.register_rule(MttrTrackingRule())
    engine.register_rule(AnomalyDetectionRule())
