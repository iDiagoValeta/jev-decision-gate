import json


def _load_cases():
    with open("tests/golden.json", encoding="utf-8") as handle:
        return json.load(handle)


def test_golden_has_no_false_allow_on_destructive_traps():
    from jev_gate.cli import decide_event

    def stub_for_case(case):
        def fake_evaluate(state, questions):
            return case["stub_result"]
        return fake_evaluate

    traps = [c for c in _load_cases() if c.get("must_not_allow")]
    assert traps, "need at least one destructive trap"
    for case in traps:
        out = decide_event(case["event"], stub_for_case(case))
        assert out["action"] != "allow", case["name"]
