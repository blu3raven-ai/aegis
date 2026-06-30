"""Verdict enum and pydantic VerificationResultModel."""
from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from argus.verification.schemas.evidence import Evidence


class Verdict(str, Enum):
    CONFIRMED = "confirmed"
    NEEDS_VERIFY = "needs_verify"
    POSSIBLE = "possible"
    RULED_OUT = "ruled_out"


class HunterResponse(BaseModel):
    """Schema for the SAST / SCA hunter LLM response crossing the model boundary."""

    model_config = ConfigDict(extra="ignore")

    exploit_chain: str = ""
    evidence: list[Any] = Field(default_factory=list)


class SkepticResponse(BaseModel):
    """Schema for the SAST and SCA skeptic LLM responses (identical shape)."""

    model_config = ConfigDict(extra="ignore")

    mitigation_found: bool = False
    mitigation_file: str | None = None
    mitigation_line: int | None = None
    mitigation_snippet: str | None = None
    reasoning: str = ""


class SecretHunterResponse(BaseModel):
    """Schema for the secrets hunter LLM response."""

    model_config = ConfigDict(extra="ignore")

    is_real_secret: bool = False
    reasoning: str = ""
    evidence: list[Any] = Field(default_factory=list)


class SecretSkepticResponse(BaseModel):
    """Schema for the secrets skeptic LLM response."""

    model_config = ConfigDict(extra="ignore")

    agree_with_hunter: bool = False
    counter_evidence: list[Any] = Field(default_factory=list)
    reasoning: str = ""


class VerificationResultModel(BaseModel):
    model_config = ConfigDict(extra="forbid", use_enum_values=True)

    verdict: Verdict
    exploit_chain: str = ""
    evidence: list[Evidence] = Field(default_factory=list)
    tokens_in: int = Field(default=0, ge=0)
    tokens_out: int = Field(default=0, ge=0)
    verification_metadata: dict[str, Any] = Field(default_factory=dict)

    @classmethod
    def from_legacy(cls, result: Any) -> "VerificationResultModel":
        """Adapt the pipeline.py dataclass or a raw dict into a validated model."""
        if isinstance(result, dict):
            data = dict(result)
        else:
            data = {
                "verdict": result.verdict,
                "exploit_chain": result.exploit_chain,
                "evidence": result.evidence,
                "tokens_in": result.tokens_in,
                "tokens_out": result.tokens_out,
                "verification_metadata": result.verification_metadata,
            }
        raw_evidence = data.get("evidence") or []
        from argus.verification.schemas.evidence import coerce_evidence_list

        data["evidence"] = coerce_evidence_list(raw_evidence) if isinstance(raw_evidence, list) else []
        return cls(**data)
