"""Cross-scanner correlated-finding schema."""
from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from runner.verification.schemas.evidence import Evidence


class ChainSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class CorrelationVerdict(str, Enum):
    CHAIN_CONFIRMED = "chain_confirmed"
    CHAIN_POSSIBLE = "chain_possible"
    NO_CHAIN = "no_chain"


class CorrelatorPayload(BaseModel):
    """Schema for the correlator agent's final JSON payload crossing the model boundary."""

    model_config = ConfigDict(extra="ignore")

    verdict: CorrelationVerdict
    chain_severity: str = "medium"
    chain_description: str = ""
    source_finding_ids: list[Any] = Field(default_factory=list)
    evidence: list[Any] = Field(default_factory=list)


class CorrelatedFinding(BaseModel):
    model_config = ConfigDict(extra="forbid", use_enum_values=True)

    correlation_id: str = Field(min_length=8)
    verdict: CorrelationVerdict
    chain_severity: ChainSeverity
    chain_description: str
    source_finding_ids: list[str] = Field(min_length=1)
    evidence: list[Evidence] = Field(default_factory=list)
    tool_call_count: int = Field(default=0, ge=0)
    tokens_in: int = Field(default=0, ge=0)
    tokens_out: int = Field(default=0, ge=0)
    metadata: dict[str, Any] = Field(default_factory=dict)
