"""The scan verification summary must bucket needs_runtime_verification, not drop
it (same fixed-key-dict gap as the findings verdict counts)."""
from src.scans.models import VerificationSummary


def test_verification_summary_accepts_needs_runtime_verification():
    s = VerificationSummary(confirmed=1, needs_runtime_verification=2, needs_verify=0)
    assert s.needs_runtime_verification == 2


def test_verification_summary_defaults_runtime_bucket_to_zero():
    assert VerificationSummary().needs_runtime_verification == 0
