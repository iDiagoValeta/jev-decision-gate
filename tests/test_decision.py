def test_low_confidence_asks_human():
    from jev_gate.decision import combine
    out = combine("allow", 0.4, 0.9, 0.1, "read")
    assert out == {"action": "ask-human", "reason": "low-confidence"}


def test_destructive_needs_high_confidence():
    from jev_gate.decision import combine
    out = combine("allow", 0.7, 0.9, 0.2, "destructive")
    assert out["action"] == "ask-human"


def test_destructive_high_confidence_allows():
    from jev_gate.decision import combine
    out = combine("allow", 0.92, 0.9, 0.2, "destructive")
    assert out["action"] == "allow"


def test_unsafe_state_degrades_to_human():
    from jev_gate.decision import combine
    out = combine("allow", 0.95, 0.1, 0.2, "read")
    assert out["action"] == "ask-human"


def test_high_risk_degrades_to_human():
    from jev_gate.decision import combine
    out = combine("allow", 0.95, 0.9, 1.8, "write")
    assert out["action"] == "ask-human"


def test_deny_passes_through():
    from jev_gate.decision import combine
    out = combine("deny", 0.9, 0.9, 0.1, "read")
    assert out["action"] == "deny"
