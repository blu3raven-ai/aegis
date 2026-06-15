"""Regression tests for the SPA static fallback path-traversal guard."""
from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost:5432/test")
os.environ.setdefault("RUNNER_ENCRYPTION_KEY", "0" * 64)


def _build_fallback(static_root: Path):
    """Reconstruct the spa_fallback handler against an arbitrary static_root.

    Mirrors the production handler in src/main.py:485.
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
