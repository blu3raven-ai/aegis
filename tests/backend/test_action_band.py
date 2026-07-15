from src.findings.action_band import ACT, ATTEND, TRACK, action_band, band_ordinal


def test_kev_and_high_is_act():
    assert action_band("critical", kev_listed=True) == ACT
    assert action_band("high", kev_listed=True) == ACT


def test_kev_low_severity_is_attend():
    assert action_band("low", kev_listed=True) == ATTEND
    assert action_band("medium", kev_listed=True) == ATTEND


def test_reachable_high_no_kev_is_attend():
    assert action_band("high", kev_listed=False, reachability="reachable") == ATTEND


def test_no_kev_no_reachable_is_track():
    assert action_band("critical", kev_listed=False) == TRACK
    assert action_band("high", kev_listed=False, reachability="no_path") == TRACK
    assert action_band("high", kev_listed=False, reachability="unknown") == TRACK
    assert action_band("high", kev_listed=False, reachability=None) == TRACK


def test_unknown_severity_is_not_elevated_to_act():
    # Absence of severity never fabricates a 'high' (no severity-driven elevation),
    # but KEV is never demoted to Track — KEV alone lands Attend.
    assert action_band(None, kev_listed=True) == ATTEND
    assert action_band("", kev_listed=True) == ATTEND
    assert action_band("bogus", kev_listed=True) == ATTEND


def test_unknown_severity_without_kev_is_track():
    assert action_band(None, kev_listed=False) == TRACK
    assert action_band("bogus", kev_listed=False) == TRACK
    # reachable only promotes with a real high+ severity, never on unknown
    assert action_band("bogus", kev_listed=False, reachability="reachable") == TRACK


def test_reachable_but_low_severity_is_track():
    # reachability only promotes when severity is high+
    assert action_band("medium", kev_listed=False, reachability="reachable") == TRACK


def test_epss_never_changes_the_band():
    # EPSS is not an input — the helper does not even accept it.
    import inspect

    assert "epss" not in inspect.signature(action_band).parameters


def test_band_ordinal_orders_act_above_attend_above_track():
    assert band_ordinal(ACT) > band_ordinal(ATTEND) > band_ordinal(TRACK)
    assert band_ordinal("nonsense") == 0
