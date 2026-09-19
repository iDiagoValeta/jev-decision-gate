def test_decide_event_allows_with_fake_evaluate():
    from jev_gate.cli import decide_event

    def fake_evaluate(state, questions):
        return {
            "decision": {"choice": "allow", "confidence": 0.92},
            "safe": {"noul": 0.95},
            "risk": {"score": 0.1, "confidence": 0.8},
            "model": "jev-1.13.0",
        }

    event = {
        "objective": "Fix login bug",
        "halt": {"kind": "read", "tool": "read", "detail": "Read src/app.py"},
        "context": {},
        "policy": {},
    }
    out = decide_event(event, fake_evaluate)
    assert out["action"] == "allow"
    assert out["model"] == "jev-1.13.0"


def test_decide_event_fail_open_on_error():
    from jev_gate.cli import decide_event

    def bad_evaluate(state, questions):
        raise RuntimeError("down")

    event = {
        "objective": "Fix login bug",
        "halt": {"kind": "destructive", "tool": "bash", "detail": "rm -rf /tmp/x"},
        "context": {},
        "policy": {},
    }
    out = decide_event(event, bad_evaluate)
    assert out == {
        "action": "ask-human",
        "reason": "fail-open",
        "pick": None,
        "confidence": 0.0,
        "model": None,
    }


def test_decide_event_uses_jev_pick_on_allow():
    from jev_gate.cli import decide_event

    def fake_evaluate(state, questions):
        return {
            "decision": {"choice": "allow", "confidence": 0.92},
            "safe": {"noul": 0.95},
            "risk": {"score": 0.1, "confidence": 0.8},
            "pick": {"choice": "b"},
            "model": "jev-1.13.0",
        }

    event = {
        "objective": "Pick lib",
        "halt": {"kind": "multichoice", "tool": "ask", "detail": "Which lib?", "options": ["a", "b"]},
        "context": {},
        "policy": {},
    }
    out = decide_event(event, fake_evaluate)
    assert out["action"] == "allow"
    assert out["pick"] == "b"


def test_decide_event_fail_open_when_pick_missing():
    from jev_gate.cli import decide_event

    def fake_evaluate(state, questions):
        return {
            "decision": {"choice": "allow", "confidence": 0.92},
            "safe": {"noul": 0.95},
            "risk": {"score": 0.1, "confidence": 0.8},
            "model": "jev-1.13.0",
        }

    event = {
        "objective": "Pick lib",
        "halt": {"kind": "multichoice", "tool": "ask", "detail": "Which lib?", "options": ["a", "b"]},
        "context": {},
        "policy": {},
    }
    out = decide_event(event, fake_evaluate)
    assert out["action"] == "ask-human"
    assert out["pick"] is None


def test_decide_event_fail_open_when_pick_invalid():
    from jev_gate.cli import decide_event

    def fake_evaluate(state, questions):
        return {
            "decision": {"choice": "allow", "confidence": 0.92},
            "safe": {"noul": 0.95},
            "risk": {"score": 0.1, "confidence": 0.8},
            "pick": {"choice": "zzz"},
            "model": "jev-1.13.0",
        }

    event = {
        "objective": "Pick lib",
        "halt": {"kind": "multichoice", "tool": "ask", "detail": "Which lib?", "options": ["a", "b"]},
        "context": {},
        "policy": {},
    }
    out = decide_event(event, fake_evaluate)
    assert out["action"] == "ask-human"
    assert out["pick"] is None
