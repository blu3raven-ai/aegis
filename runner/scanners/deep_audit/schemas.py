"""Schema for the authz hunter's per-file response. Precision/verdict schemas are
reused from runner.verification.schemas (SkepticResponse, HunterResponse)."""
from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class AuthzCandidate(BaseModel):
    """One claimed broken-access-control flaw, before verification."""

    model_config = ConfigDict(extra="ignore")

    title: str = ""
    endpoint: str = ""
    file: str = ""
    line: int = 0
    severity: str = "medium"
    weakness: str = ""  # missing_authorization | missing_object_scope
    exploit_chain: str = ""
    evidence: list[Any] = Field(default_factory=list)
    reproduction: str = ""
    fix: str = ""


class AuthzHunterResponse(BaseModel):
    """The authz hunter reasons over a whole handler file and may emit several
    candidates (one per flawed endpoint)."""

    model_config = ConfigDict(extra="ignore")

    findings: list[AuthzCandidate] = Field(default_factory=list)
