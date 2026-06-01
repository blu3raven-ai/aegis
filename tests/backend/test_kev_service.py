"""Tests for KevService.

KevService uses run_db() internally (like api_keys/service.py), so tests call
the synchronous methods directly — no async wrangling needed.
"""
from __future__ import annotations

from datetime import date

import pytest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _sample_entries(n: int = 3, prefix: str = "") -> list[dict]:
    today = date.today()
    entries = []
    for i in range(n):
        entries.append({
            "cve_id": f"CVE-2024-SVC{prefix}{10000 + i}",
            "vendor_project": "Example Vendor",
            "product": f"Product {i}",
            "vulnerability_name": f"Test Vuln {i}",
            "date_added": today,
            "short_description": f"Description {i}",
            "required_action": "Patch immediately.",
            "due_date": date(2024, 12, 31),
            "known_ransomware_use": i % 2 == 0,
            "notes": "",
            "cwes": ["CWE-20"],
        })
    return entries


# ---------------------------------------------------------------------------
# upsert_catalog
# ---------------------------------------------------------------------------

def test_upsert_returns_new_count():
    """First upsert of N entries returns N (all are new)."""
    from src.kev.service import KevService
    service = KevService()
    entries = _sample_entries(3, prefix="A")
    new_count = service.upsert_catalog(entries)
    assert new_count == 3


def test_upsert_idempotent():
    """Re-upserting the same entries returns 0 new entries."""
    from src.kev.service import KevService
    service = KevService()
    entries = _sample_entries(2, prefix="B")
    service.upsert_catalog(entries)
    new_count = service.upsert_catalog(entries)
    assert new_count == 0


def test_upsert_updates_existing_fields():
    """Upsert with changed field values updates the row in place."""
    from src.kev.service import KevService
    service = KevService()
    cve_id = "CVE-2024-SVC88888"
    original = {
        "cve_id": cve_id,
        "vendor_project": "OriginalVendor",
        "product": "OriginalProduct",
        "vulnerability_name": "Original Name",
        "date_added": date.today(),
        "short_description": "Old desc",
        "required_action": "Old action",
        "due_date": date(2024, 6, 1),
        "known_ransomware_use": False,
        "notes": "",
        "cwes": [],
    }
    service.upsert_catalog([original])

    updated = {**original, "vulnerability_name": "Updated Name", "known_ransomware_use": True}
    service.upsert_catalog([updated])

    entry = service.get_entry(cve_id)
    assert entry is not None
    assert entry.vulnerability_name == "Updated Name"
    assert entry.known_ransomware_use is True


def test_upsert_empty_list_returns_zero():
    from src.kev.service import KevService
    service = KevService()
    count = service.upsert_catalog([])
    assert count == 0


# ---------------------------------------------------------------------------
# get_entry
# ---------------------------------------------------------------------------

def test_get_entry_found():
    from src.kev.service import KevService
    service = KevService()
    cve_id = "CVE-2024-SVC77777"
    service.upsert_catalog([{
        "cve_id": cve_id,
        "vendor_project": "TestVendor",
        "product": "TestProduct",
        "vulnerability_name": "Test Vulnerability",
        "date_added": date.today(),
        "short_description": "A test",
        "required_action": "Patch",
        "due_date": date(2024, 12, 1),
        "known_ransomware_use": False,
        "notes": "",
        "cwes": [],
    }])
    entry = service.get_entry(cve_id)
    assert entry is not None
    assert entry.cve_id == cve_id


def test_get_entry_not_found():
    from src.kev.service import KevService
    service = KevService()
    entry = service.get_entry("CVE-9999-SVC00000")
    assert entry is None


# ---------------------------------------------------------------------------
# list_recent
# ---------------------------------------------------------------------------

def test_list_recent_returns_within_window():
    from src.kev.service import KevService
    service = KevService()
    recent_cve = "CVE-2024-SVC55555"
    old_cve = "CVE-2020-SVC55555"
    service.upsert_catalog([
        {
            "cve_id": recent_cve,
            "vendor_project": "V",
            "product": "P",
            "vulnerability_name": "Recent Vuln",
            "date_added": date.today(),
            "short_description": "",
            "required_action": "",
            "due_date": None,
            "known_ransomware_use": False,
            "notes": "",
            "cwes": [],
        },
        {
            "cve_id": old_cve,
            "vendor_project": "V",
            "product": "P",
            "vulnerability_name": "Old Vuln",
            "date_added": date(2020, 1, 1),
            "short_description": "",
            "required_action": "",
            "due_date": None,
            "known_ransomware_use": False,
            "notes": "",
            "cwes": [],
        },
    ])

    results = service.list_recent(days=30)
    cve_ids = [e.cve_id for e in results]
    assert recent_cve in cve_ids
    assert old_cve not in cve_ids


# ---------------------------------------------------------------------------
# get_exposure_summary
# ---------------------------------------------------------------------------

def test_exposure_summary_structure_empty_org():
    """Returns the expected keys with zero counts for an org with no findings."""
    from src.kev.service import KevService
    service = KevService()
    summary = service.get_exposure_summary("kev-test-empty-org-xyz")

    assert "open_findings_total" in summary
    assert "open_findings_in_kev" in summary
    assert "kev_overdue" in summary
    assert "kev_with_ransomware" in summary
    assert "top_kev_findings" in summary
    assert isinstance(summary["top_kev_findings"], list)
    assert summary["open_findings_total"] == 0
    assert summary["open_findings_in_kev"] == 0
