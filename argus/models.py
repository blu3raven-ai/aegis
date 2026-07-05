"""Request/response models for the Argus verification API."""
from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

# Scanner families Argus can verify today. Mirrors the runner-side verifier seam.
Scanner = Literal["code_scanning", "iac", "secrets"]


class CodeFile(BaseModel):
    """One source slice the verifier reads from the materialized repo_root."""

    path: str
    content: str


class CodeContext(BaseModel):
    """The code slices to materialize on disk for a single finding."""

    files: list[CodeFile] = Field(default_factory=list)


class VerifyFinding(BaseModel):
    """A single finding to verify.

    ``detail`` is the raw finding dict the verifier expects and is passed
    straight through as ``finding`` — it must carry whatever keys the verifier
    reads (``file``, ``line``, ``verified``, etc.).
    """

    finding_id: str
    detail: dict[str, Any]
    code_context: CodeContext = Field(default_factory=CodeContext)


class VerifyRequest(BaseModel):
    scan_id: str
    scanner: Scanner
    findings: list[VerifyFinding] = Field(default_factory=list)


class VerifyResult(BaseModel):
    finding_id: str
    verdict: str
    confidence: float | None = None
    exploit_chain: str = ""
    evidence: list[dict[str, Any]] = Field(default_factory=list)
    reachability: str | None = None
    recommended_fix: str | None = None
    rationale: str | None = None
    source: str = "argus"
    verification_metadata: dict[str, Any] = Field(default_factory=dict)


class VerifyResponse(BaseModel):
    results: list[VerifyResult] = Field(default_factory=list)


class MatchComponent(BaseModel):
    """One SBOM component to match.

    ``purl`` + ``version`` is the minimum; Argus derives the ecosystem and
    package name from the purl. An integrator that already holds the canonical
    coordinate (e.g. from its SBOM) should also send ``name`` (canonical package
    name) and ``ecosystem`` (OSV name, e.g. ``PyPI``) for exact matching — these
    take precedence over purl derivation.
    """

    purl: str | None = None
    version: str
    name: str | None = None
    ecosystem: str | None = None


class MatchRequest(BaseModel):
    surface: str
    components: list[MatchComponent]


class MatchPackage(BaseModel):
    name: str
    ecosystem: str | None = None


class MatchAdvisory(BaseModel):
    id: str
    cve_id: str | None = None
    severity: str | None = None
    cvss_score: float | None = None
    cvss_vector: str | None = None
    summary: str = ""
    description: str = ""
    html_url: str = ""
    references: list[dict[str, Any]] = Field(default_factory=list)
    published_at: str = ""
    vulnerable_version_range: str = ""
    first_patched_version: str | None = None


class PremiumIntel(BaseModel):
    """The premium intelligence delta that the free OSV mirror cannot produce.

    Every field here is the value Argus adds on top of a public advisory: signal
    that comes from the live intel feed rather than from a static vulnerability
    database. It rides along each premium match so the consumer can prioritise
    far more precisely than severity alone. The Argus premium feed populates
    these; on a free-tier match the object is absent.
    """

    # Whether the vuln is actively exploited, has public PoC, or neither.
    exploit_maturity: Literal["in_the_wild", "poc", "none"] | None = None
    # Symbol-level narrowing: the functions whose presence makes a package
    # version actually reachable/affected (lets the consumer drop noise).
    affected_functions: list[str] = Field(default_factory=list)
    # Maturity/trust signal for the package itself (e.g. abandonment, typo-squat).
    package_reputation: str | None = None
    epss_score: float | None = None
    epss_provenance: str | None = None
    kev_listed: bool = False
    # The alias graph: every identifier (CVE/GHSA/vendor) that resolves to this
    # advisory, so callers can dedupe across feeds.
    aliases: list[str] = Field(default_factory=list)
    # Provenance + freshness of this record in the premium feed.
    source: str | None = None
    last_synced: str | None = None


class MatchItem(BaseModel):
    """A single premium advisory hit against one component."""

    package: MatchPackage
    version: str
    manifest_path: str = ""
    advisory: MatchAdvisory
    # The premium delta for this hit. Additive: free-tier consumers ignore it,
    # premium-aware consumers prioritise on it.
    intel: PremiumIntel | None = None


class MatchResponse(BaseModel):
    matches: list[MatchItem] = Field(default_factory=list)
class CorrelateFinding(BaseModel):
    """A single raw finding fed to the cross-scanner correlator.

    Unlike ``VerifyFinding`` there is no top-level ``finding_id`` — correlation
    keys off the id carried inside ``detail`` (alongside ``repository`` and the
    scanner fields the correlator groups on).
    """

    detail: dict[str, Any]
    code_context: CodeContext = Field(default_factory=CodeContext)


class CorrelateRequest(BaseModel):
    budget: int = 50000
    # Required so a caller that omits the batch fails loudly (422) rather than
    # silently correlating nothing.
    findings: list[CorrelateFinding]


class CorrelateResponse(BaseModel):
    correlated_findings: list[dict[str, Any]] = Field(default_factory=list)
