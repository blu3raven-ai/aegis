"""Unit tests for the data_retention action schema discriminator."""
from __future__ import annotations

import pytest
from pydantic import TypeAdapter, ValidationError

from src.rules.action_schemas import DataRetentionAction, validate_action_for_category


_ADAPTER = TypeAdapter(DataRetentionAction)


def test_archive_action_accepts_valid_payload():
    model = _ADAPTER.validate_python({"type": "archive", "after_days": 365})
    assert model.type == "archive"
    assert model.after_days == 365


def test_delete_action_accepts_valid_payload():
    model = _ADAPTER.validate_python({"type": "delete", "after_days": 365})
    assert model.type == "delete"
    assert model.after_days == 365


def test_archive_action_floor_is_30_days():
    with pytest.raises(ValidationError):
        _ADAPTER.validate_python({"type": "archive", "after_days": 29})


def test_archive_action_accepts_30_days_exactly():
    _ADAPTER.validate_python({"type": "archive", "after_days": 30})


def test_delete_action_floor_is_90_days():
    with pytest.raises(ValidationError):
        _ADAPTER.validate_python({"type": "delete", "after_days": 89})


def test_delete_action_accepts_90_days_exactly():
    _ADAPTER.validate_python({"type": "delete", "after_days": 90})


def test_action_ceiling_is_3650_days():
    with pytest.raises(ValidationError):
        _ADAPTER.validate_python({"type": "archive", "after_days": 3651})


def test_archive_action_accepts_3650_days_exactly():
    _ADAPTER.validate_python({"type": "archive", "after_days": 3650})


def test_delete_action_accepts_3650_days_exactly():
    _ADAPTER.validate_python({"type": "delete", "after_days": 3650})


def test_delete_action_rejects_3651_days():
    with pytest.raises(ValidationError):
        _ADAPTER.validate_python({"type": "delete", "after_days": 3651})


def test_data_retention_category_now_supported():
    model = validate_action_for_category(
        "data_retention", {"type": "archive", "after_days": 365}
    )
    assert model.type == "archive"
    assert model.after_days == 365


def test_unknown_type_rejected():
    with pytest.raises(ValidationError):
        _ADAPTER.validate_python({"type": "purge", "after_days": 365})
