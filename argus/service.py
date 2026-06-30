"""Argus verification service.

Hosts the LLM verification agent loop (copied from the Aegis runner) behind a
thin HTTP seam so the runner can call it as a stateless client. The verifiers
read code from a filesystem ``repo_root``; this service materializes each
finding's shipped code slices into a temp dir and passes that as ``repo_root``,
which lets the copied verification code run unchanged.
"""
from __future__ import annotations

import logging
import os
import shutil
import tempfile
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from argus.auth import AuthError, TokenClaims, get_verifier
from argus.matching import match_components
from argus.models import (
    CodeContext,
    MatchRequest,
    MatchResponse,
    CorrelateRequest,
    CorrelateResponse,
    VerifyFinding,
    VerifyRequest,
    VerifyResponse,
    VerifyResult,
)
from argus.verification.budget import ScanBudget
from argus.verification.llm_client import LlmClient
from argus.verification.pipeline import (
    VerificationResult,
    verify_finding,
    verify_secret_finding,
)
from argus.verification.pipelines.multiscanner import correlate_findings
from argus.verification.verifiers.iac import verify_iac_finding

logger = logging.getLogger(__name__)

app = FastAPI(title="Argus", version="0.1.0")

# Extracts the Bearer credential; verification happens in argus.auth.
_bearer = HTTPBearer(auto_error=True)


def build_llm() -> LlmClient:
    """Construct the LLM client from environment.

    Module-level factory so tests can monkeypatch it with a fake client and
    exercise the full round-trip without a real key.
    """
    return LlmClient(
        api_key=os.environ.get("LLM_API_KEY", ""),
        api_base_url=os.environ.get("LLM_API_BASE_URL", ""),
        model=os.environ.get("LLM_API_MODEL", ""),
    )


def _require_bearer(
    creds: HTTPAuthorizationCredentials = Depends(_bearer),
) -> TokenClaims:
    """Verify the bearer token and return its claims, or 401.

    Delegates to the configured verifier (static dev secret, or real JWT/JWKS in
    production — see ``argus.auth``). ``claims.org_id`` is the tenant boundary the
    handlers must scope on.
    """
    try:
        return get_verifier().verify(creds.credentials or "")
    except AuthError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc


def _materialize_repo(code_context: CodeContext, root: Path) -> None:
    """Write each shipped code slice under ``root``, jailed against traversal."""
    root = root.resolve()
    for f in code_context.files:
        rel = Path(f.path)
        if rel.is_absolute() or ".." in rel.parts:
            raise ValueError(f"unsafe code_context path: {f.path}")
        dest = (root / rel).resolve()
        if not dest.is_relative_to(root):
            raise ValueError(f"path escapes repo_root: {f.path}")
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(f.content, encoding="utf-8")


def _to_result(finding_id: str, vr: VerificationResult) -> VerifyResult:
    return VerifyResult(
        finding_id=finding_id,
        verdict=vr.verdict,
        exploit_chain=vr.exploit_chain,
        evidence=list(vr.evidence or []),
        verification_metadata=dict(vr.verification_metadata or {}),
    )


def _verify_one(scanner: str, finding: VerifyFinding, llm: LlmClient) -> VerifyResult:
    """Materialize slices into a temp repo and run the matching verifier.

    Per-finding errors are caught and mapped to a ``needs_verify`` result so a
    single bad finding never fails the whole batch (fail-open).
    """
    tmp = tempfile.mkdtemp(prefix="argus-repo-")
    try:
        _materialize_repo(finding.code_context, Path(tmp))
        if scanner == "code_scanning":
            vr = verify_finding(finding=finding.detail, repo_root=tmp, llm=llm)
        elif scanner == "secrets":
            vr = verify_secret_finding(finding=finding.detail, repo_root=tmp, llm=llm)
        elif scanner == "iac":
            vr = verify_iac_finding(finding=finding.detail, repo_root=tmp, llm=llm)
        else:  # pragma: no cover - request validation rejects this first
            raise ValueError(f"unsupported scanner: {scanner}")
        return _to_result(finding.finding_id, vr)
    except Exception as exc:  # noqa: BLE001 - fail-open per finding
        logger.warning("argus verify failed for %s: %s", finding.finding_id, exc)
        return VerifyResult(
            finding_id=finding.finding_id,
            verdict="needs_verify",
            verification_metadata={"error": str(exc)},
        )
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def _correlate_batch(body: CorrelateRequest) -> list[dict]:
    """Materialize each repo's slices into one shared root, then run the correlator.

    The correlator greps across a whole repository group, so every finding in a
    given ``repository`` must land in the same root — one temp dir per distinct
    repository key, with every slice for that repo written into it. Correlation
    is best-effort: any failure fails open to an empty result rather than 500ing
    the batch.
    """
    roots: dict[str, Path] = {}
    try:
        for f in body.findings:
            key = (f.detail.get("repository") or "").strip()
            root = roots.get(key)
            if root is None:
                root = Path(tempfile.mkdtemp(prefix="argus-corr-"))
                roots[key] = root
            _materialize_repo(f.code_context, root)

        result = correlate_findings(
            [f.detail for f in body.findings],
            repo_root_for=roots,
            llm=build_llm(),
            budget=ScanBudget(scan_budget=body.budget, daily_remaining=1_000_000),
        )
        return [c.model_dump() for c in result]
    except Exception as exc:  # noqa: BLE001 - correlation is best-effort
        logger.warning("argus correlate batch failed: %s", exc)
        return []
    finally:
        for root in roots.values():
            shutil.rmtree(root, ignore_errors=True)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/v1/verify", response_model=VerifyResponse)
def verify(
    body: VerifyRequest,
    _claims: TokenClaims = Depends(_require_bearer),
) -> VerifyResponse:
    llm = build_llm()
    results = [_verify_one(body.scanner, f, llm) for f in body.findings]
    return VerifyResponse(results=results)


@app.post("/v1/match", response_model=MatchResponse)
def match(
    body: MatchRequest,
    claims: TokenClaims = Depends(_require_bearer),
) -> MatchResponse:
    matches = match_components(body.surface, body.components, org_id=claims.org_id)
    return MatchResponse(matches=matches)
@app.post("/v1/correlate", response_model=CorrelateResponse)
def correlate(
    body: CorrelateRequest,
    _claims: TokenClaims = Depends(_require_bearer),
) -> CorrelateResponse:
    if not body.findings:
        return CorrelateResponse(correlated_findings=[])
    return CorrelateResponse(correlated_findings=_correlate_batch(body))
