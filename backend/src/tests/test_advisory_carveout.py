from src.findings.advisory import compose_advisory_markdown, compose_advisory_html


_FINDING = {
    "title": "eval RCE",
    "verdict": "ruled_out",
    "verification_metadata": {
        "ruled_out_reason": {
            "source": "accepted_risk",
            "risk_id": "3",
            "statement": "eval is a sandboxed plugin loader",
        }
    },
}


def test_advisory_markdown_notes_accepted_risk_carveout() -> None:
    md = compose_advisory_markdown(_FINDING)
    assert "accepted risk" in md.lower()
    assert "sandboxed plugin loader" in md


def test_advisory_html_notes_accepted_risk_carveout() -> None:
    html = compose_advisory_html(_FINDING)
    assert "accepted risk" in html.lower()
    assert "sandboxed plugin loader" in html
