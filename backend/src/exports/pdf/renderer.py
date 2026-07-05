"""Thin wrapper around WeasyPrint. The only public entry point is render_pdf."""
from __future__ import annotations

from io import BytesIO


def render_pdf(html: str, *, base_url: str | None = None) -> bytes:
    """Render an HTML string to a PDF byte string.

    base_url controls how relative URLs inside the HTML resolve. Pass None to
    disable resolution. Callers MUST html-escape any untrusted content
    upstream (Jinja autoescape) — WeasyPrint will follow file:// and http(s)://
    URLs encountered in the rendered HTML.
    """
    # Lazy import: WeasyPrint requires native libs (libpango, libcairo, ...) at
    # import time, not just at render time. Importing eagerly breaks pytest
    # collection on dev machines without those libs even when no PDF is rendered.
    from weasyprint import HTML  # noqa: PLC0415

    buf = BytesIO()
    HTML(string=html, base_url=base_url).write_pdf(target=buf)
    return buf.getvalue()
