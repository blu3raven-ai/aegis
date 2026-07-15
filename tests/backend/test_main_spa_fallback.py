"""Regression tests for the SPA static fallback path-traversal guard."""
from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost:5432/test")
os.environ.setdefault("APP_SECRET", "0" * 64)

from src.main import _resolve_export_html  # noqa: E402


def _build_fallback(static_root: Path):
    """Reconstruct the spa_fallback handler against an arbitrary static_root.

    Mirrors the production handler in src/main.py, delegating dynamic-route
    stub resolution to the real ``_resolve_export_html`` so the two can't drift.
    """
    static_root_resolved = static_root.resolve()

    app = FastAPI()

    @app.get("/{path:path}")
    async def spa_fallback(path: str) -> FileResponse:
        try:
            candidate = (static_root_resolved / path).resolve()
        except (OSError, RuntimeError, ValueError):
            raise HTTPException(status_code=400, detail="invalid path")
        if not candidate.is_relative_to(static_root_resolved):
            raise HTTPException(status_code=400, detail="invalid path")
        if candidate.is_file():
            return FileResponse(candidate)
        html_candidate = candidate.parent / f"{candidate.name}.html"
        if html_candidate.is_file() and html_candidate.is_relative_to(static_root_resolved):
            return FileResponse(html_candidate, media_type="text/html")
        parts = [p for p in path.strip("/").split("/") if p]
        stub_html = _resolve_export_html(static_root_resolved, parts)
        if stub_html is not None:
            return FileResponse(stub_html, media_type="text/html")
        return FileResponse(static_root_resolved / "index.html", media_type="text/html")

    return spa_fallback, static_root_resolved


@pytest.mark.parametrize(
    "evil_path",
    [
        # Starlette URL-decodes %2e%2e to .. before handing the path to the
        # handler, so these are the post-decode forms we must catch.
        "../etc/passwd",
        "/etc/passwd",
        "subdir/../../etc/passwd",
    ],
)
def test_fallback_rejects_traversal(evil_path: str) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "index.html").write_text("<html></html>")
        handler, _ = _build_fallback(root)
        import asyncio

        with pytest.raises(HTTPException) as exc:
            asyncio.run(handler(evil_path))
        assert exc.value.status_code == 400


def test_fallback_serves_valid_static_file() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "index.html").write_text("<html></html>")
        (root / "assets").mkdir()
        (root / "assets" / "logo.svg").write_text("<svg></svg>")
        handler, _ = _build_fallback(root)
        import asyncio

        result = asyncio.run(handler("assets/logo.svg"))
        assert isinstance(result, FileResponse)
        assert str(result.path).endswith("logo.svg")


def test_fallback_returns_index_for_unknown_route() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "index.html").write_text("<html></html>")
        handler, _ = _build_fallback(root)
        import asyncio

        result = asyncio.run(handler("dashboard"))
        assert isinstance(result, FileResponse)
        assert str(result.path).endswith("index.html")


def test_fallback_serves_prerendered_html_for_route() -> None:
    """A route with a sibling "<route>.html" (Next export, trailingSlash:false)
    must serve that page, not the app index — otherwise /login renders the
    authenticated shell instead of the login form."""
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "index.html").write_text("<html>app shell</html>")
        (root / "login.html").write_text("<html>login form</html>")
        # The export also emits a "login/" directory (for /login/verify), so the
        # bare "login" path resolves to a directory, not a file.
        (root / "login").mkdir()
        (root / "login" / "verify.html").write_text("<html>verify</html>")
        handler, _ = _build_fallback(root)
        import asyncio

        result = asyncio.run(handler("login"))
        assert isinstance(result, FileResponse)
        assert str(result.path).endswith("login.html")

        nested = asyncio.run(handler("login/verify"))
        assert str(nested.path).endswith("verify.html")


def _build_export_tree(root: Path) -> None:
    """Lay down a static export mirroring the app's real dynamic-route stubs.

    Next's generateStaticParams emits "_" as the placeholder segment, so a
    dynamic route ships as "<literal.../>_.html" (single dynamic segment) or,
    for a route with two dynamic segments, "compliance/_/_.html".
    """
    (root / "index.html").write_text("<html>shell</html>")
    (root / "404.html").write_text("<html>not found</html>")
    # Single dynamic segment: /findings/<id> -> findings/_.html
    (root / "findings").mkdir()
    (root / "findings" / "_.html").write_text("<html>finding</html>")
    # Literal parent + dynamic child: /sources/<id> and /sources/<id>/findings
    sources = root / "sources"
    sources.mkdir()
    (sources / "_.html").write_text("<html>source</html>")
    (sources / "_").mkdir()
    (sources / "_" / "findings.html").write_text("<html>source findings</html>")
    # Literal sibling next to the dynamic stub: /sources/code-repositories/<id>
    (sources / "code-repositories").mkdir()
    (sources / "code-repositories" / "_.html").write_text("<html>repo source</html>")
    # Two dynamic segments: /compliance/<framework>/<controlId>
    compliance = root / "compliance"
    compliance.mkdir()
    (compliance / "_").mkdir()
    (compliance / "_" / "_.html").write_text("<html>control detail</html>")


@pytest.mark.parametrize(
    ("path", "expected_suffix"),
    [
        # Single dynamic segment (already worked before the fix).
        ("findings/abc123", "findings/_.html"),
        # Nested two-dynamic-segment route — the regression: must resolve the
        # compliance/_/_.html shell, not fall through to the 404 document.
        ("compliance/iso27001/A.8.8", "compliance/_/_.html"),
        # Mixed literal + dynamic segments.
        ("sources/xyz/findings", "sources/_/findings.html"),
        # A literal child sibling of the dynamic stub wins (static precedence).
        ("sources/code-repositories/xyz", "sources/code-repositories/_.html"),
    ],
)
def test_resolve_export_html_matches_dynamic_stubs(path: str, expected_suffix: str) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp).resolve()
        _build_export_tree(root)
        parts = [p for p in path.split("/") if p]
        resolved = _resolve_export_html(root, parts)
        assert resolved is not None, f"{path!r} should resolve to a stub"
        assert str(resolved).endswith(expected_suffix)


@pytest.mark.parametrize(
    "path",
    [
        "does-not-exist",
        "compliance/iso27001/A.8.8/extra",  # too deep for the two-segment stub
        "sources/xyz/unknown-tab",  # no sources/_/unknown-tab.html
    ],
)
def test_resolve_export_html_returns_none_for_unknown(path: str) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp).resolve()
        _build_export_tree(root)
        parts = [p for p in path.split("/") if p]
        assert _resolve_export_html(root, parts) is None


def test_fallback_serves_nested_dynamic_control_detail() -> None:
    """End-to-end through the handler: a compliance control-detail deeplink
    (/compliance/<framework>/<controlId>) must serve the compliance/_/_.html
    shell rather than the app index or 404 document."""
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        _build_export_tree(root)
        handler, _ = _build_fallback(root)
        import asyncio

        result = asyncio.run(handler("compliance/iso27001/A.8.8"))
        assert isinstance(result, FileResponse)
        assert str(result.path).endswith("compliance/_/_.html")
