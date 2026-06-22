"""Shared `pdf_skip` marker for WeasyPrint-dependent tests.

WeasyPrint segfaults during font loading on macOS in pytest environments
(weasyprint/text/fonts.py:103 → native Pango/Fontconfig call on Apple Silicon).
The same tests pass on the Linux CI image. Skip locally on macOS so the rest
of the suite can complete; restore by exporting RUN_PDF_TESTS=1.
"""
from __future__ import annotations

import os
import sys

import pytest

pdf_skip = pytest.mark.skipif(
    sys.platform == "darwin" and not os.environ.get("RUN_PDF_TESTS"),
    reason="WeasyPrint font init segfaults on macOS; set RUN_PDF_TESTS=1 to opt in",
)
