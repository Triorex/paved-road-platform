import vuln_triage as vt


def test_kev_always_wins():
    assert vt.priority("low", True, 0.0) == "P0"


def test_epss_escalates_medium():
    assert vt.priority("medium", False, 0.62) == "P1"
    assert vt.priority("medium", False, 0.2) == "P2"


def test_severity_mapping():
    assert vt.priority("critical", False, None) == "P1"
    assert vt.priority("high", False, None) == "P2"
    assert vt.priority("medium", False, None) == "P3"
    assert vt.priority("", False, None) == "P4"
