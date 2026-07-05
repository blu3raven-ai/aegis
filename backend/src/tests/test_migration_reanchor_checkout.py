"""Unit-tests the pure transforms in the _checkout re-anchor data migration.

The DB rewrite itself is exercised against a real Postgres in the migration
run; here we lock the invariant that matters for correctness: rewriting an
existing identity key by substring-replacing the escaped file_path yields the
*exact* key ingest now produces for the re-anchored path. If that byte-match
ever broke, the migration would orphan findings instead of preserving them.
"""
import importlib.util
from pathlib import Path

from src.code_scanning.ingest import code_finding_identity

_MIGRATION = (
    Path(__file__).resolve().parents[2]
    / "alembic"
    / "versions"
    / "37051b2b381d_reanchor_sast_file_path_off_checkout_.py"
)


def _load():
    spec = importlib.util.spec_from_file_location("_reanchor_migration", _MIGRATION)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_reanchor_matches_ingest():
    mod = _load()
    assert mod._reanchor("acme-repo/_checkout/app/db.py") == "app/db.py"
    assert mod._reanchor("app/db.py") == "app/db.py"


def test_key_rewrite_byte_matches_recomputed_clean_key():
    mod = _load()
    repo, rule, line, snippet = "acme/api", "py.sqli", 12, "query(x)"
    old_fp = "acme-repo/_checkout/app/db.py"
    new_fp = mod._reanchor(old_fp)

    old_key = code_finding_identity(repo, old_fp, rule, line, snippet)
    rewritten = old_key.replace(mod._esc(old_fp), mod._esc(new_fp), 1)

    # The migration's rewrite must equal a from-scratch identity on the clean
    # path — same string the next scan's ingest will produce.
    assert rewritten == code_finding_identity(repo, new_fp, rule, line, snippet)
    assert "_checkout" not in rewritten


def test_key_rewrite_survives_colon_in_repo():
    mod = _load()
    # Colons are escaped to %3A in every component, so a colon in the repo can't
    # be confused with the file_path segment the migration targets.
    repo, rule, line, snippet = "host:8080/acme", "py.sqli", 3, "x"
    old_fp = "r/_checkout/a.py"
    new_fp = mod._reanchor(old_fp)
    old_key = code_finding_identity(repo, old_fp, rule, line, snippet)
    rewritten = old_key.replace(mod._esc(old_fp), mod._esc(new_fp), 1)
    assert rewritten == code_finding_identity(repo, new_fp, rule, line, snippet)
