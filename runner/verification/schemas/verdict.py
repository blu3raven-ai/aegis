"""Verdict enum and pydantic VerificationResultModel."""
from __future__ import annotations

from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from runner.verification.schemas.evidence import Evidence


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
    # A specific, human-readable title for the confirmed finding — the vector, not
    # the generic rule name (e.g. "SSRF via x-forward-url header lets an attacker
    # read cloud metadata"). Replaces semgrep's rule message in the UI when present.
    title: str = ""
    # One concrete sentence: what an attacker actually achieves (account takeover,
    # read any tenant's data, key exfiltration). The "Impact" line of a real report.
    impact: str = ""
    # A concise, descriptive reproduction outline for a confirmed chain — the
    # steps that demonstrate reachability, not a weaponised payload. Optional;
    # only surfaced when the model provides one.
    reproduction: str = ""
    # Distinct routes an attacker can take to the same sink, each a
    # {"name": ..., "steps": "... [R1] ..."} object citing the evidence. A single
    # obvious path stays in exploit_chain; this is for the genuinely multi-path
    # cases (e.g. a validated route AND an unvalidated passthrough).
    attack_paths: list[Any] = Field(default_factory=list)
    # What limits real-world exploitability (default bind, upstream auth, feature
    # gating). Calibrates severity and mirrors a real audit report's section.
    mitigating_factors: list[str] = Field(default_factory=list)
    # A concrete remediation for the confirmed finding — a unified diff when the
    # fix is small (--- a/file / +++ b/file / @@), else 1-3 sentences naming the
    # exact change. Semgrep rarely ships a usable autofix for these, so the model
    # writes one; rendered as a diff in the drawer.
    fix: str = ""
    # Eight CVSS 3.1 base metrics, each a single-letter enum. The model
    # CLASSIFIES the axes; it never emits a score — the score is computed
    # deterministically downstream. Empty dict when the model can't classify.
    #   AV: N|A|L|P  AC: L|H  PR: N|L|H  UI: N|R
    #   S:  U|C      C:  N|L|H  I: N|L|H  A: N|L|H
    cvss_metrics: dict[str, str] = Field(default_factory=dict)
    # Why this confirmed finding is materially distinct from any published
    # CVE/GHSA it resembles (different sink / trigger / component). Optional.
    distinctness: str = ""
    # Numbered defense-in-depth remediation steps beyond the primary `fix` diff.
    remediation: list[Any] = Field(default_factory=list)
    # Runnable benign proof-of-concept that drives the REAL vulnerable path with
    # a benign marker (no weaponisation). Body only — the safe-harbor header is
    # templated server-side at download time.
    poc_script: str = ""
    poc_filename: str = ""
    poc_language: str = ""


class SkepticResponse(BaseModel):
    """Schema for the SAST and SCA skeptic LLM responses (identical shape)."""

    model_config = ConfigDict(extra="ignore")

    mitigation_found: bool = False
    mitigation_file: str | None = None
    mitigation_line: int | None = None
    mitigation_snippet: str | None = None
    reasoning: str = ""


class DepsReachabilityResponse(BaseModel):
    """Schema for the dependency reachability LLM response.

    ``reachability`` is a strict tri-state — an out-of-range value fails
    validation so the caller can fail safe to ``unknown`` rather than trust a
    guessed label.
    """

    model_config = ConfigDict(extra="ignore")

    reachability: Literal["reachable", "no_path", "unknown"]
    evidence: list[Any] = Field(default_factory=list)


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
        from runner.verification.schemas.evidence import coerce_evidence_list

        data["evidence"] = coerce_evidence_list(raw_evidence) if isinstance(raw_evidence, list) else []
        return cls(**data)
