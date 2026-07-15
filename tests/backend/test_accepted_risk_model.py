from src.db.models import AcceptedRisk


def test_accepted_risk_tablename_and_columns() -> None:
    cols = {c.name for c in AcceptedRisk.__table__.columns}
    assert AcceptedRisk.__tablename__ == "accepted_risk"
    assert {"id", "asset_id", "source_connection_id", "statement",
            "path_glob", "rule_id", "scanner", "enabled", "created_by", "created_at"} <= cols
