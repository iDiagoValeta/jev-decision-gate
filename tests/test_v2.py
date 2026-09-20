def test_write_executes_on_jev_say_so():
    from jev_gate import decision
    low = decision.combine("allow", 0.15, 0.1, 1.9, "write")
    assert low == {"action": "allow", "reason": "jev-allow"}
    denied = decision.combine("deny", 0.9, 0.9, 0.1, "write")
    assert denied == {"action": "deny", "reason": "jev-deny"}


def test_no_pick_question_without_options():
    from jev_gate.schemas import build_questions
    out = build_questions({"kind": "multichoice", "tool": "question", "detail": "x"})
    assert "pick" not in out
    out2 = build_questions({"kind": "multichoice", "tool": "question", "detail": "x", "options": ["a"]})
    assert out2["pick"]["type"] == "choice"


def test_multichoice_without_options_flows_through():
    from jev_gate.cli import decide_event

    def fake(state, questions):
        assert "pick" not in questions
        return {"decision": {"choice": "allow", "confidence": 0.8},
                "safe": {"noul": 0.9}, "risk": {"score": 0.2, "confidence": 0.8},
                "model": "m"}

    event = {"objective": "o", "halt": {"kind": "multichoice", "tool": "question", "detail": "x"},
             "context": {}, "policy": {}}
    out = decide_event(event, fake)
    assert out == {"action": "allow", "reason": "jev-allow", "pick": None,
                   "confidence": 0.8, "model": "m"}


def test_fail_open_carries_error():
    from jev_gate.cli import decide_event

    def bad(state, questions):
        raise RuntimeError("down")

    out = decide_event({"objective": "o", "halt": {"kind": "read"}}, bad)
    assert out["reason"] == "fail-open" and out["error"] == "exception"


def test_multichoice_pick_recorded_on_allow():
    from jev_gate.cli import decide_event

    def fake_evaluate(state, questions):
        return {
            "decision": {"choice": "allow", "confidence": 0.34},
            "safe": {"noul": 0.2},
            "risk": {"score": 1.9, "confidence": 0.9},
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


def test_redact_secrets():
    from jev_gate.schemas import build_objective_block, redact_secrets
    assert "[REDACTED" in redact_secrets("Bearer abcdefgh1234")
    assert "[REDACTED" in redact_secrets("key=ghp_12345678901234567890")
    assert "BEGIN RSA" not in redact_secrets("-----BEGIN RSA PRIVATE KEY-----")
    brief = build_objective_block("Fix x with ghp_12345678901234567890",
                                  {"kind": "read", "tool": "read", "detail": "Read f"})
    assert "ghp_" not in brief
    assert brief.startswith("OBJECTIVE:")


def test_brief_state_has_hash():
    from jev_gate.schemas import build_state, sha256_hex
    st = build_state("Do x", {"kind": "write", "detail": "echo hi"}, {}, {})
    assert "brief" in st and "OBJECTIVE:" in st["brief"]
    assert st["detail_sha256"] == sha256_hex("echo hi")


def test_cli_log_schema_v2(tmp_path, monkeypatch):
    import json

    import jev_gate.cli as cli_mod
    from jev_gate.cli import decide_event, main

    def fake(state, questions):
        return {"decision": {"choice": "allow", "confidence": 0.9},
                "safe": {"noul": 0.9}, "risk": {"score": 0.1, "confidence": 0.8},
                "model": "m", "usage": {"input_tokens": 42}}

    event = {"objective": "o", "halt": {"kind": "read", "tool": "read", "detail": "Read f"},
             "context": {"sessionID": "s1", "requestID": "r1"}, "policy": {}}
    out = decide_event(event, fake)
    assert out["usage"] == {"input_tokens": 42}

    log = tmp_path / "log.jsonl"
    monkeypatch.setenv("JEV_GATE_LOG", str(log))
    monkeypatch.setenv("TYPESAFE_API_KEY", "x")
    monkeypatch.setattr(cli_mod.client_mod, "evaluate",
                        lambda state, questions, api_key, model: fake(state, questions))
    import io
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(event)))
    monkeypatch.setattr("sys.stdout", io.StringIO())
    main()
    row = json.loads(log.read_text().strip())
    assert row["v"] == 2
    assert row["sessionID"] == "s1" and row["requestID"] == "r1"
    assert row["gateAction"] == "allow" and row["usage"] == {"input_tokens": 42}
    assert "detail_sha256" in row and len(row["detail_sha256"]) == 64
