def test_build_state_keeps_named_fields():
    from jev_gate.schemas import build_state
    halt = {"kind": "read", "tool": "read", "detail": "Read src/app.py"}
    out = build_state("Fix login bug", halt, {"cwd": "/repo"}, {"default": "ask-human when unsure"})
    assert out["objective"] == "Fix login bug"
    assert out["halt"] == {"kind": "read", "tool": "read", "detail": "Read src/app.py"}
    assert out["context"] == {"cwd": "/repo"}
    assert out["policy"] == {"default": "ask-human when unsure"}
    assert "brief" in out and out["brief"].startswith("OBJECTIVE:")
    assert len(out["detail_sha256"]) == 64


def test_build_questions_has_parallel_trio():
    from jev_gate.schemas import build_questions
    halt = {"kind": "read", "tool": "read", "detail": "Read src/app.py"}
    out = build_questions(halt)
    assert out["decision"]["type"] == "choice"
    assert out["safe"]["type"] == "noul"
    assert out["risk"]["type"] == "score"
    assert "allow" in out["decision"]["criteria"]


def test_multichoice_adds_pick_question():
    from jev_gate.schemas import build_questions
    halt = {"kind": "multichoice", "tool": "ask", "detail": "Which lib?", "options": ["a", "b"]}
    out = build_questions(halt)
    assert out["pick"]["type"] == "choice"
    assert set(out["pick"]["criteria"].keys()) == {"a", "b"}


def test_redact_secrets_is_safe_on_non_string_and_empty_input():
    from jev_gate.schemas import redact_secrets
    assert redact_secrets(None) == ""
    assert redact_secrets(123) == ""
    assert redact_secrets([]) == ""
    assert redact_secrets("") == ""


def test_build_objective_block_falls_back_when_objective_is_empty():
    from jev_gate.schemas import build_objective_block
    halt = {"kind": "read", "tool": "read", "detail": "Read src/app.py"}
    brief = build_objective_block("", halt)
    assert "[objective-missing]" in brief
    brief_whitespace = build_objective_block("   ", halt)
    assert "[objective-missing]" in brief_whitespace


def test_build_objective_block_truncates_objective_and_detail():
    from jev_gate.schemas import build_objective_block
    long_objective = "x" * 9000
    long_detail = "z" * 2000
    halt = {"kind": "write", "tool": "bash", "detail": long_detail}
    brief = build_objective_block(long_objective, halt)
    # Objective is capped to the last 8000 chars (neither "x" nor "z" appear
    # in the fixed boilerplate text, so a plain count is exact here).
    assert brief.count("x") == 8000
    # Detail is capped to the first 1500 chars.
    assert brief.count("z") == 1500


def test_build_objective_block_defaults_kind_and_tool_when_missing():
    from jev_gate.schemas import build_objective_block
    brief = build_objective_block("Do the task", {})
    assert "kind=write" in brief
    assert "tool=?" in brief


def test_build_objective_block_keeps_multiturn_context():
    # The plugin now sends a bounded multi-turn transcript (default budget
    # 4000 chars), not just the last user message. This cap must not
    # re-truncate it back down to the old 500-char single-turn window.
    from jev_gate.schemas import build_objective_block
    transcript = "User: turn one\n" + ("Assistant: filler line\n" * 100) + "User: do the actual task now"
    assert len(transcript) > 500
    halt = {"kind": "read", "tool": "read", "detail": "Read src/app.py"}
    brief = build_objective_block(transcript, halt)
    assert "do the actual task now" in brief
    assert "turn one" in brief
