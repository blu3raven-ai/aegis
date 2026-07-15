from src.findings.advisory import compose_advisory_markdown, compose_advisory_html

_F = {"title": "SSRF", "verdict": "needs_runtime_verification",
      "verification_metadata": {"runtime_question": "Confirm /fetch is served without auth in prod"}}

def test_markdown_renders_runtime_question():
    md = compose_advisory_markdown(_F)
    assert "runtime verification" in md.lower()
    assert "without auth" in md

def test_html_renders_runtime_question():
    html = compose_advisory_html(_F)
    assert "runtime verification" in html.lower()
    assert "without auth" in html
