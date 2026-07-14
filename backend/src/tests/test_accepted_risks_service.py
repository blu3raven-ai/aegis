from src.sources.accepted_risks_service import matched_for_repo

_A = "11111111-1111-1111-1111-111111111111"
_B = "22222222-2222-2222-2222-222222222222"


def test_matched_for_repo_filters_disabled_and_scopes() -> None:
    rows = [
        {"id": 1, "asset_id": _A, "enabled": True, "statement": "a"},
        {"id": 2, "asset_id": _A, "enabled": False, "statement": "b"},   # disabled
        {"id": 3, "asset_id": _B, "enabled": True, "statement": "c"},    # other asset
        {"id": 4, "asset_id": None, "enabled": True, "statement": "d"},  # unscoped — must NOT match
    ]
    out = matched_for_repo(rows, asset_id=_A)
    ids = {r["id"] for r in out}
    # Strictly this asset's own enabled risks. A null-asset row never leaks in
    # (that was the cross-source suppression bug); disabled + other-asset excluded.
    assert ids == {1}
