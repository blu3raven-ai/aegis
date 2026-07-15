"""Unit tests for the top-level OSV refresh job.

The refresh job ties fetcher → store → reconcile together:
  1. Read last successful refresh timestamp.
  2. Fetch advisories per configured ecosystem.
  3. Upsert into Postgres + MinIO.
  4. Compute changed_advisory_ids (modified_at > last_run_finished_at).
  5. Reconcile affected SBOMs in-backend.
  6. Record summary to osv_refresh_runs.
"""
from __future__ import annotations

import pytest

from src.jobs.osv_refresh import refresh_osv_catalog


@pytest.fixture(autouse=True)
def _limit_ecosystems(monkeypatch):
    monkeypatch.setenv("OSV_ECOSYSTEMS", "npm,pypi")


def test_refresh_invokes_fetcher_store_reconcile(monkeypatch):
    """Happy path — every ecosystem fetched, stored, reconciled."""
    fetched: list[tuple[str, int]] = []
    stored: list[tuple[str, int]] = []

    def _fake_fetch(ecosystem: str):
        return iter([{"id": f"GHSA-{ecosystem}-1"}])

    async def _fake_upsert(self, advisories, *, ecosystem):
        adv_list = list(advisories)
        stored.append((ecosystem, len(adv_list)))
        return len(adv_list)

    async def _fake_changed(self, since):
        return ["GHSA-npm-1", "GHSA-pypi-1"]

    async def _fake_reconcile(ids, *, refresh_run_id=None):
        return len(set(ids))

    monkeypatch.setattr("src.jobs.osv_refresh.fetch_ecosystem",
                        lambda eco: (fetched.append((eco, 1)), _fake_fetch(eco))[1])
    monkeypatch.setattr("src.osv.store.OsvStore.upsert_advisories", _fake_upsert)
    monkeypatch.setattr("src.osv.store.OsvStore.list_changed_since", _fake_changed)
    monkeypatch.setattr("src.jobs.osv_refresh.reconcile_sbom_matches", _fake_reconcile)

    result = refresh_osv_catalog()

    assert {e for e, _ in fetched} == {"npm", "pypi"}
    assert {e for e, _ in stored} == {"npm", "pypi"}
    assert result["advisories_changed"] == 2
    assert result["findings_reconciled"] == 2
    assert "runtime_ms" in result
    assert result.get("error") is None


def test_refresh_records_run_to_osv_refresh_runs_table(monkeypatch):
    """An osv_refresh_runs row is written even when reconcile yields 0 findings."""
    monkeypatch.setattr("src.jobs.osv_refresh.fetch_ecosystem", lambda eco: iter([]))

    async def _fake_upsert(self, advisories, *, ecosystem):
        return 0

    async def _fake_changed(self, since):
        return []

    async def _fake_reconcile(ids, *, refresh_run_id=None):
        return 0

    monkeypatch.setattr("src.osv.store.OsvStore.upsert_advisories", _fake_upsert)
    monkeypatch.setattr("src.osv.store.OsvStore.list_changed_since", _fake_changed)
    monkeypatch.setattr("src.jobs.osv_refresh.reconcile_sbom_matches", _fake_reconcile)

    result = refresh_osv_catalog()

    assert result["advisories_changed"] == 0
    assert result["findings_reconciled"] == 0
    assert result["error"] is None


def test_refresh_continues_after_per_ecosystem_failure(monkeypatch):
    """If one ecosystem fetch fails, other ecosystems still get processed."""
    def _fetch(ecosystem):
        if ecosystem == "npm":
            raise RuntimeError("simulated network failure")
        return iter([{"id": f"GHSA-{ecosystem}-1"}])

    upserts: list[str] = []

    async def _fake_upsert(self, advisories, *, ecosystem):
        upserts.append(ecosystem)
        return 1

    async def _fake_changed(self, since):
        return []

    async def _fake_reconcile(ids, *, refresh_run_id=None):
        return 0

    monkeypatch.setattr("src.jobs.osv_refresh.fetch_ecosystem", _fetch)
    monkeypatch.setattr("src.osv.store.OsvStore.upsert_advisories", _fake_upsert)
    monkeypatch.setattr("src.osv.store.OsvStore.list_changed_since", _fake_changed)
    monkeypatch.setattr("src.jobs.osv_refresh.reconcile_sbom_matches", _fake_reconcile)

    result = refresh_osv_catalog()

    assert upserts == ["pypi"]
    assert "npm" in (result.get("error") or "")
