"""The needs_runtime_verification verdict must get its own count bucket, not just
fold into total (else the drawer's filter chip reads 0)."""
from src.findings.resolvers import FindingsVerdictCounts


def test_verdict_counts_exposes_needs_runtime_verification():
    out = {
        "total": 3, "confirmed": 1, "needs_runtime_verification": 2,
        "needs_verify": 0, "possible": 0, "ruled_out": 0, "legacy": 0,
    }
    counts = FindingsVerdictCounts(**out)
    assert counts.needs_runtime_verification == 2
    assert counts.total == 3
