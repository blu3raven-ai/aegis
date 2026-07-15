"""Authz deep-audit: an LLM reasoning pass for broken access control (missing
authorization + IDOR/BOLA) — the one class semgrep structurally can't pattern-match.
It is a thin candidate generator; precision (skeptic, citation critic, ground-truth
carve-outs, needs_runtime_verification) is delegated to the shared runner.verification
pipeline, not reimplemented."""
