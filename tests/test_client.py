def test_evaluate_normalizes_answers():
    from jev_gate.client import evaluate

    def fake_transport(state, questions, model):
        return {
            "model": "jev-1.13.0",
            "answers": {
                "decision": {"type": "choice", "choice": "allow", "confidence": 0.9},
                "safe": {"type": "noul", "noul": 0.95},
                "risk": {"type": "score", "score": 0.2, "confidence": 0.8},
            },
        }

    out = evaluate({"objective": "x"}, {"decision": {}}, api_key="k", transport=fake_transport)
    assert out["decision"] == {"choice": "allow", "confidence": 0.9}
    assert out["safe"] == {"noul": 0.95}
    assert out["model"] == "jev-1.13.0"


def test_evaluate_raises_on_transport_error():
    import pytest

    from jev_gate.client import JevCallError, evaluate

    def bad_transport(state, questions, model):
        raise RuntimeError("boom")

    with pytest.raises(JevCallError):
        evaluate({}, {}, api_key="k", transport=bad_transport)


def test_evaluate_raises_missing_api_key_on_empty_key():
    import pytest

    from jev_gate.client import JevCallError, evaluate

    with pytest.raises(JevCallError, match="missing-api-key"):
        evaluate({}, {}, api_key="")


def test_evaluate_wraps_malformed_answers_as_bad_response():
    import pytest

    from jev_gate.client import JevCallError, evaluate

    def missing_keys_transport(state, questions, model):
        return {"model": "jev-1.13.0", "answers": {"decision": {"choice": "allow"}}}

    with pytest.raises(JevCallError, match="bad-response"):
        evaluate({"objective": "x"}, {"decision": {}}, api_key="k", transport=missing_keys_transport)


def test_evaluate_wraps_non_numeric_confidence_as_bad_response():
    import pytest

    from jev_gate.client import JevCallError, evaluate

    def bad_confidence_transport(state, questions, model):
        return {
            "model": "jev-1.13.0",
            "answers": {
                "decision": {"choice": "allow", "confidence": "not-a-number"},
                "safe": {"noul": 0.95},
                "risk": {"score": 0.2, "confidence": 0.8},
            },
        }

    with pytest.raises(JevCallError, match="bad-response"):
        evaluate({"objective": "x"}, {"decision": {}}, api_key="k", transport=bad_confidence_transport)


def test_evaluate_returns_pick_when_present():
    from jev_gate.client import evaluate

    def fake_transport(state, questions, model):
        return {
            "model": "jev-1.13.0",
            "answers": {
                "decision": {"type": "choice", "choice": "allow", "confidence": 0.9},
                "safe": {"type": "noul", "noul": 0.95},
                "risk": {"type": "score", "score": 0.2, "confidence": 0.8},
                "pick": {"type": "choice", "choice": "b"},
            },
        }

    out = evaluate({"objective": "x"}, {"decision": {}}, api_key="k", transport=fake_transport)
    assert out["pick"] == {"choice": "b"}
