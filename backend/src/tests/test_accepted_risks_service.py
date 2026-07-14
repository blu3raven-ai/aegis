from src.sources.accepted_risks_service import matched_for_repo

_A = "11111111-1111-1111-1111-111111111111"
_B = "22222222-2222-2222-2222-222222222222"


def test_matched_for_repo_filters_disabled_and_scopes() -> None:
    rows = [
        {"id": 1, "asset_id": _A, "enabled": True, "statement": "a"},
        {"id": 2, "asset_id": _A, "enabled": False, "statement": "b"},
        {"id": 3, "asset_id": _B, "enabled": True, "statement": "c"},
        {"id": 4, "asset_id": None, "enabled": True, "statement": "d"},  # source-wide
    ]
    out = matched_for_repo(rows, asset_id=_A)
    ids = {r["id"] for r in out}
    assert ids == {1, 4}  # enabled + (asset match or source-wide); disabled + other-asset excluded
