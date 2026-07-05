from src.exports.pdf import render_pdf
from src.tests._pdf_skip import pdf_skip


@pdf_skip
def test_render_pdf_returns_pdf_bytes():
    html = "<html><body><h1>Hello</h1></body></html>"
    result = render_pdf(html)
    assert result[:4] == b"%PDF"
    assert len(result) > 500


@pdf_skip
def test_render_pdf_accepts_full_html_document():
    html = '<html><head><title>Test Doc</title></head><body><p>x</p></body></html>'
    result = render_pdf(html)
    assert b"%PDF" in result[:8]


@pdf_skip
def test_render_pdf_with_no_base_url():
    html = "<html><body><p>x</p></body></html>"
    result = render_pdf(html, base_url=None)
    assert result[:4] == b"%PDF"
