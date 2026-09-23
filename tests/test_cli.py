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
        "error": "exception",
        "error_detail": "down",
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
    error_box = {}
    out = decide_event(event, fake_evaluate, error_box)
    assert out["action"] == "ask-human"
    assert out["pick"] is None
    assert error_box["error_class"] == "bad-response"


def test_decide_event_pick_ignored_on_deny_even_with_options():
    from jev_gate.cli import decide_event

    def fake_evaluate(state, questions):
        return {
            "decision": {"choice": "deny", "confidence": 0.92},
            "safe": {"noul": 0.1},
            "risk": {"score": 0.9, "confidence": 0.8},
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
    assert out["action"] == "deny"
    assert out["pick"] is None


def test_decide_event_non_dict_pick_fails_open_not_crashes():
    from jev_gate.cli import decide_event

    def fake_evaluate(state, questions):
        return {
            "decision": {"choice": "allow", "confidence": 0.92},
            "safe": {"noul": 0.95},
            "risk": {"score": 0.1, "confidence": 0.8},
            "pick": "not-a-dict",
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


def test_decide_event_missing_objective_or_halt_fails_open():
    from jev_gate.cli import decide_event

    error_box = {}
    out = decide_event({}, lambda state, questions: {}, error_box)
    assert out["action"] == "ask-human" and out["reason"] == "fail-open"
    assert error_box["error_class"] == "exception"

    error_box2 = {}
    out2 = decide_event({"objective": "o", "halt": None}, lambda state, questions: {}, error_box2)
    assert out2["action"] == "ask-human" and out2["reason"] == "fail-open"
    assert error_box2["error_class"] == "exception"


def test_decide_event_classifies_bad_response_from_client_error():
    from jev_gate.cli import decide_event
    from jev_gate.client import JevCallError

    def bad_evaluate(state, questions):
        raise JevCallError("bad-response: 'decision'")

    event = {"objective": "o", "halt": {"kind": "read"}, "context": {}, "policy": {}}
    error_box = {}
    out = decide_event(event, bad_evaluate, error_box)
    assert out["action"] == "ask-human" and out["reason"] == "fail-open"
    assert error_box["error_class"] == "bad-response"


def test_classify_error_maps_known_prefixes():
    from jev_gate.cli import _classify_error
    from jev_gate.client import JevCallError

    assert _classify_error(JevCallError("missing-api-key")) == "missing-key"
    assert _classify_error(JevCallError("bad-response: 'decision'")) == "bad-response"
    assert _classify_error(JevCallError("missing-sdk: no module named typesafe_sdk")) == "transport"
    assert _classify_error(JevCallError("connection reset")) == "transport"
    assert _classify_error(RuntimeError("boom")) == "exception"
    assert _classify_error(None) == "exception"
