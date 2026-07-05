"""Public API for the PDF export module."""
from pathlib import Path

from src.exports.pdf.renderer import render_pdf

TEMPLATE_DIR = Path(__file__).parent / "templates"

__all__ = ["render_pdf", "TEMPLATE_DIR"]
