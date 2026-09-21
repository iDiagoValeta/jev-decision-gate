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


def test_real_transport_normalizes_object_style_sdk_answers():
    from unittest.mock import MagicMock, patch

    from jev_gate.client import _real_transport

    class FakeAnswer:
        def __init__(self, type_, **kw):
            self.type = type_
            for k, v in kw.items():
                setattr(self, k, v)

    class FakeResult:
        model = "jev-1.13.0"
        usage = {"input_tokens": 42}
        answers = {
            "decision": FakeAnswer("choice", choice="allow", confidence=0.9),
            "safe": FakeAnswer("noul", noul=0.95),
            "risk": FakeAnswer("score", score=0.2, confidence=0.8),
        }

    fake_client = MagicMock()
    fake_client.__enter__.return_value = fake_client
    fake_client.__exit__.return_value = False
    fake_client.system_one.return_value = FakeResult()

    with patch("typesafe_sdk.TypeSafeClient", return_value=fake_client):
        out = _real_transport({"objective": "x"}, {"decision": {}}, api_key="k", model="jev-latest")

    assert out["answers"]["decision"] == {"type": "choice", "choice": "allow", "confidence": 0.9}
    assert out["answers"]["safe"] == {"type": "noul", "noul": 0.95}
    assert out["usage"] == {"input_tokens": 42}


def test_real_transport_swallows_malformed_usage_without_raising():
    from unittest.mock import MagicMock, patch

    from jev_gate.client import _real_transport

    class FakeAnswer:
        def __init__(self, type_, **kw):
            self.type = type_
            for k, v in kw.items():
                setattr(self, k, v)

    class FakeResult:
        model = "jev-1.13.0"
        usage = {"input_tokens": "not-a-number"}
        answers = {
            "decision": FakeAnswer("choice", choice="allow", confidence=0.9),
            "safe": FakeAnswer("noul", noul=0.95),
            "risk": FakeAnswer("score", score=0.2, confidence=0.8),
        }

    fake_client = MagicMock()
    fake_client.__enter__.return_value = fake_client
    fake_client.__exit__.return_value = False
    fake_client.system_one.return_value = FakeResult()

    with patch("typesafe_sdk.TypeSafeClient", return_value=fake_client):
        out = _real_transport({"objective": "x"}, {"decision": {}}, api_key="k", model="jev-latest")

    assert "usage" not in out


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
