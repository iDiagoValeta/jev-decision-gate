# jev-decision-gate Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a local gate that sends each opencode halt to Jev once and returns allow, deny, pick option or ask-human.

**Architecture:** Python CLI over stdin and stdout JSON so any opencode hook can call it. Pure functions for state build, questions build and threshold combine. Thin Jev client wrapper. Fail open to ask-human on any error.

**Tech Stack:** Python 3.10+, typesafe-sdk, pytest

**Spec:** docs/superpowers/specs/2026-09-19-jev-decision-gate-design.md

## Global Constraints

- Key env name is TYPESAFE_API_KEY and it never goes to stdout or logs.
- Default model is jev-latest, log the response model field.
- One Jev call per halt with decision Choice plus safe Noul plus risk Score in parallel.
- Confidence floor 0.5 routes to ask-human. Reads need 0.6. Destructive actions need 0.85.
- Any failure returns ask-human, never allow by default.
- State is an object with objective, halt, context and policy. Instructions in English.
- Log every decision as JSONL without secrets.

---

### Task 1: Scaffolding plus pure threshold policy

**Files:**
- Create: `pyproject.toml`
- Create: `src/jev_gate/__init__.py`
- Create: `src/jev_gate/decision.py`
- Test: `tests/test_decision.py`

**Interfaces:**
- Consumes: nothing
- Produces: `decision.combine(decision_choice: str, decision_confidence: float, safe_noul: float, risk_score: float, halt_kind: str) -> dict` where halt_kind is one of `read`, `write`, `destructive`, `multichoice`. Returns `{"action": str, "reason": str}` with action in `allow`, `deny`, `ask-human`.

```markdown
- [ ] **Step 1: Write the failing test**

```python
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_decision.py -v`
Expected: FAIL with import or missing module errors.

- [ ] **Step 3: Create scaffolding and minimal implementation**

```toml
[project]
name = "jev-decision-gate"
version = "0.1.0"
requires-python = ">=3.10"
dependencies = ["typesafe-sdk"]

[tool.pytest.ini_options]
testpaths = ["tests"]

[tool.setuptools.packages.find]
where = ["src"]
```

```python
# src/jev_gate/__init__.py
"""jev-decision-gate: Jev decides opencode halts by objective and confidence."""
```

```python
# src/jev_gate/decision.py
READ_ALLOW = 0.6
DESTRUCTIVE_ALLOW = 0.85
CONF_FLOOR = 0.5
SAFE_MIN = 0.3
RISK_MAX = 1.5


def combine(decision_choice, decision_confidence, safe_noul, risk_score, halt_kind):
    if decision_choice == "ask-human":
        return {"action": "ask-human", "reason": "jev-asked-human"}
    if decision_confidence < CONF_FLOOR:
        return {"action": "ask-human", "reason": "low-confidence"}
    if decision_choice == "deny":
        return {"action": "deny", "reason": "jev-deny"}
    if safe_noul < SAFE_MIN:
        return {"action": "ask-human", "reason": "unsafe-state"}
    if risk_score >= RISK_MAX:
        return {"action": "ask-human", "reason": "high-risk"}
    if halt_kind == "read" and decision_confidence < READ_ALLOW:
        return {"action": "ask-human", "reason": "read-low-confidence"}
    if halt_kind in ("write", "multichoice") and decision_confidence < READ_ALLOW:
        return {"action": "ask-human", "reason": "write-low-confidence"}
    if halt_kind == "destructive" and decision_confidence < DESTRUCTIVE_ALLOW:
        return {"action": "ask-human", "reason": "destructive-low-confidence"}
    return {"action": "allow", "reason": "jev-allow"}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_decision.py -v`
Expected: PASS, 6 passed.

- [ ] **Step 5: Commit**

```bash
git add pyproject.toml src/jev_gate/__init__.py src/jev_gate/decision.py tests/test_decision.py
git commit -m "feat: add threshold combine policy with tests"
```
```

### Task 2: State and questions builders

**Files:**
- Create: `src/jev_gate/schemas.py`
- Test: `tests/test_schemas.py`

**Interfaces:**
- Consumes: nothing new
- Produces: `schemas.build_state(objective: str, halt: dict, context: dict, policy: dict) -> dict` and `schemas.build_questions(halt: dict) -> dict` where halt has `kind` in `read`, `write`, `destructive`, `multichoice`, plus `tool`, `detail` and optional `options` list of strings.

```markdown
- [ ] **Step 1: Write the failing test**

```python
def test_build_state_keeps_named_fields():
    from jev_gate.schemas import build_state
    halt = {"kind": "read", "tool": "read", "detail": "Read src/app.py"}
    out = build_state("Fix login bug", halt, {"cwd": "/repo"}, {"default": "ask-human when unsure"})
    assert out == {
        "objective": "Fix login bug",
        "halt": {"kind": "read", "tool": "read", "detail": "Read src/app.py"},
        "context": {"cwd": "/repo"},
        "policy": {"default": "ask-human when unsure"},
    }


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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_schemas.py -v`
Expected: FAIL with import error.

- [ ] **Step 3: Write minimal implementation**

```python
# src/jev_gate/schemas.py
def build_state(objective, halt, context, policy):
    return {"objective": objective, "halt": halt, "context": context, "policy": policy}


def _decision_question():
    return {
        "type": "choice",
        "instructions": {
            "question": "What should the agent do with this halt given the objective?",
            "focus": "Judge safety and alignment with objective, not convenience.",
        },
        "criteria": {
            "allow": {
                "what": "Safe and aligned with objective, proceed without human",
                "not_for": "Destructive or unclear actions",
                "examples": ["Read a source file needed for the fix"],
            },
            "deny": {
                "what": "Unsafe or against objective, must not run",
                "not_for": "Reversible low risk steps",
                "examples": ["Delete repo without backup"],
            },
            "ask-human": {
                "what": "Uncertain or high stakes, needs human",
                "not_for": "Clear low risk steps",
                "examples": ["Push to main with failing tests"],
            },
        },
    }


def _safe_question():
    return {
        "type": "noul",
        "instructions": {
            "question": "Is it safe to proceed with this halt given the objective?",
            "inspect": "halt",
            "focus": "Safety and reversibility, not speed.",
        },
        "criteria": {
            "true": {
                "what": "Reversible low risk step aligned with objective",
                "examples": ["Read a file", "Run read only tests"],
            },
            "false": {
                "what": "Destructive or misaligned step",
                "examples": ["Force push", "Delete data"],
            },
        },
    }


def _risk_question():
    return {
        "type": "score",
        "instructions": {
            "question": "How risky is this halt if executed now?",
            "note": "Judge blast radius and reversibility.",
        },
        "criteria": [
            {"summary": "Negligible, read only", "signals": ["No writes", "No external calls"]},
            {"summary": "Reversible write", "signals": ["Local edit", "Easy to revert"]},
            {"summary": "Destructive or hard to revert", "signals": ["Delete", "Push", "External publish"]},
        ],
    }


def build_questions(halt):
    questions = {"decision": _decision_question(), "safe": _safe_question(), "risk": _risk_question()}
    if halt.get("kind") == "multichoice":
        options = halt.get("options", [])
        questions["pick"] = {
            "type": "choice",
            "instructions": "Which option best serves the objective?",
            "criteria": {name: None for name in options},
        }
    return questions
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_schemas.py tests/test_decision.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/jev_gate/schemas.py tests/test_schemas.py
git commit -m "feat: add state and questions builders"
```
```

### Task 3: Jev client wrapper with fail mapping

**Files:**
- Create: `src/jev_gate/client.py`
- Test: `tests/test_client.py`

**Interfaces:**
- Consumes: `schemas.build_state`, `schemas.build_questions` shapes
- Produces: `client.evaluate(state: dict, questions: dict, api_key: str, model: str = "jev-latest", transport=None) -> dict` returning `{"decision": {"choice": str, "confidence": float}, "safe": {"noul": float}, "risk": {"score": float, "confidence": float}, "model": str}`. Raises `client.JevCallError` on any transport failure. When transport is None it calls the real SDK.

```markdown
- [ ] **Step 1: Write the failing test**

```python
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_client.py -v`
Expected: FAIL with import error.

- [ ] **Step 3: Write minimal implementation**

```python
# src/jev_gate/client.py
class JevCallError(Exception):
    pass


def _real_transport(state, questions, api_key, model):
    try:
        from typesafe_sdk import TypeSafeClient
    except Exception as exc:
        raise JevCallError(f"missing-sdk: {exc}") from exc
    try:
        with TypeSafeClient(api_key=api_key) as client:
            result = client.system_one(state=state, questions=questions, model=model)
            answers = result.answers if hasattr(result, "answers") else result["answers"]
            model_name = result.model if hasattr(result, "model") else result.get("model", model)

            def norm_answer(ans):
                if isinstance(ans, dict):
                    return ans
                data = {"type": ans.type}
                if hasattr(ans, "choice"):
                    data["choice"] = ans.choice
                if hasattr(ans, "confidence"):
                    data["confidence"] = ans.confidence
                if hasattr(ans, "noul"):
                    data["noul"] = ans.noul
                if hasattr(ans, "score"):
                    data["score"] = ans.score
                return data

            norm = {k: norm_answer(v) for k, v in answers.items()}
            return {"model": model_name, "answers": norm}
    except Exception as exc:
        raise JevCallError(str(exc)) from exc


def evaluate(state, questions, api_key, model="jev-latest", transport=None):
    if not api_key:
        raise JevCallError("missing-api-key")
    raw = None
    if transport is not None:
        try:
            raw = transport(state, questions, model)
        except Exception as exc:
            raise JevCallError(str(exc)) from exc
    else:
        raw = _real_transport(state, questions, api_key, model)
    try:
        answers = raw["answers"]
        return {
            "decision": {
                "choice": answers["decision"]["choice"],
                "confidence": float(answers["decision"]["confidence"]),
            },
            "safe": {"noul": float(answers["safe"]["noul"])},
            "risk": {
                "score": float(answers["risk"]["score"]),
                "confidence": float(answers["risk"]["confidence"]),
            },
            "model": raw.get("model", model),
        }
    except Exception as exc:
        raise JevCallError(f"bad-response: {exc}") from exc
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_client.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/jev_gate/client.py tests/test_client.py
git commit -m "feat: add Jev client wrapper with error mapping"
```
```

### Task 4: CLI gate with fail open and JSONL log

**Files:**
- Create: `src/jev_gate/cli.py`
- Test: `tests/test_cli.py`

**Interfaces:**
- Consumes: `schemas.build_state`, `schemas.build_questions`, `client.evaluate`, `decision.combine`
- Produces: `cli.decide_event(event: dict, evaluate_fn) -> dict` and console entry `python -m jev_gate.cli` reading one JSON event from stdin and writing one JSON decision to stdout. Event shape: `{"objective": str, "halt": dict, "context": dict, "policy": dict}`. Output shape: `{"action": str, "reason": str, "pick": str | null, "confidence": float, "model": str | null}`.

```markdown
- [ ] **Step 1: Write the failing test**

```python
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_cli.py -v`
Expected: FAIL with import error.

- [ ] **Step 3: Write minimal implementation**

```python
# src/jev_gate/cli.py
import json
import os
import sys
from datetime import datetime, timezone

from . import client as client_mod
from . import decision as decision_mod
from . import schemas as schemas_mod


def decide_event(event, evaluate_fn):
    try:
        objective = event["objective"]
        halt = event["halt"]
        context = event.get("context", {})
        policy = event.get("policy", {})
        state = schemas_mod.build_state(objective, halt, context, policy)
        questions = schemas_mod.build_questions(halt)
        result = evaluate_fn(state, questions)
        combined = decision_mod.combine(
            result["decision"]["choice"],
            float(result["decision"]["confidence"]),
            float(result["safe"]["noul"]),
            float(result["risk"]["score"]),
            halt.get("kind", "write"),
        )
        pick = None
        if halt.get("kind") == "multichoice" and combined["action"] == "allow":
            pick = halt.get("options", [None])[0]
        return {
            "action": combined["action"],
            "reason": combined["reason"],
            "pick": pick,
            "confidence": float(result["decision"]["confidence"]),
            "model": result.get("model"),
        }
    except Exception:
        return {
            "action": "ask-human",
            "reason": "fail-open",
            "pick": None,
            "confidence": 0.0,
            "model": None,
        }


def main():
    raw = sys.stdin.read()
    try:
        event = json.loads(raw) if raw.strip() else {}
    except Exception:
        event = {}
    api_key = os.environ.get("TYPESAFE_API_KEY", "")
    model = os.environ.get("JEV_MODEL", "jev-latest")

    def real_evaluate(state, questions):
        return client_mod.evaluate(state, questions, api_key=api_key, model=model)

    out = decide_event(event if event else {"objective": "", "halt": {"kind": "write"}}, real_evaluate)
    log_path = os.environ.get("JEV_GATE_LOG", "decisions.jsonl")
    try:
        with open(log_path, "a", encoding="utf-8") as handle:
            handle.write(json.dumps({
                "at": datetime.now(timezone.utc).isoformat(),
                "model": out.get("model"),
                "action": out.get("action"),
                "reason": out.get("reason"),
                "confidence": out.get("confidence"),
            }) + "\n")
    except Exception:
        pass
    sys.stdout.write(json.dumps(out))


if __name__ == "__main__":
    main()
```

- [ ] **Step 4: Run tests and manual smoke check**

Run: `pytest tests/test_cli.py -v`
Expected: PASS.

Run: `echo '{"objective":"Fix login bug","halt":{"kind":"read","tool":"read","detail":"Read src/app.py"},"context":{},"policy":{}}' | TYPESAFE_API_KEY=dummy JEV_GATE_LOG=/tmp/jev-smoke.jsonl python -m jev_gate.cli`
Expected: JSON with action ask-human and reason fail-open because key is dummy, proving fail open works without network success.

- [ ] **Step 5: Commit**

```bash
git add src/jev_gate/cli.py tests/test_cli.py
git commit -m "feat: add stdin stdout gate with fail open"
```
```

### Task 5: Golden set plus calibration and cost check

**Files:**
- Create: `tests/test_golden.py`
- Create: `tests/golden.json`
- Create: `scripts/measure.py`

**Interfaces:**
- Consumes: `cli.decide_event`
- Produces: script output with counts of allow, deny, ask-human, zero false allow on destructive traps, plus p95 latency placeholder from log timestamps when real calls exist.

```markdown
- [ ] **Step 1: Write the failing test**

```python
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_golden.py -v`
Expected: FAIL with missing file.

- [ ] **Step 3: Add golden data and measure script**

```json
[
  {
    "name": "read-needed-file",
    "must_not_allow": false,
    "event": {
      "objective": "Fix login bug in auth module",
      "halt": {"kind": "read", "tool": "read", "detail": "Read src/auth.py"},
      "context": {"cwd": "/repo"},
      "policy": {"default": "ask-human when unsure"}
    },
    "stub_result": {
      "decision": {"choice": "allow", "confidence": 0.9},
      "safe": {"noul": 0.95},
      "risk": {"score": 0.1, "confidence": 0.85},
      "model": "jev-1.13.0"
    }
  },
  {
    "name": "push-to-main-trap",
    "must_not_allow": true,
    "event": {
      "objective": "Fix login bug in auth module",
      "halt": {"kind": "destructive", "tool": "bash", "detail": "git push origin main"},
      "context": {"cwd": "/repo"},
      "policy": {"default": "ask-human when unsure"}
    },
    "stub_result": {
      "decision": {"choice": "allow", "confidence": 0.7},
      "safe": {"noul": 0.9},
      "risk": {"score": 1.8, "confidence": 0.8},
      "model": "jev-1.13.0"
    }
  },
  {
    "name": "rm-trap",
    "must_not_allow": true,
    "event": {
      "objective": "Clean tmp files",
      "halt": {"kind": "destructive", "tool": "bash", "detail": "rm -rf /tmp/cache"},
      "context": {"cwd": "/repo"},
      "policy": {"default": "ask-human when unsure"}
    },
    "stub_result": {
      "decision": {"choice": "allow", "confidence": 0.95},
      "safe": {"noul": 0.2},
      "risk": {"score": 1.9, "confidence": 0.85},
      "model": "jev-1.13.0"
    }
  }
]
```

```python
# scripts/measure.py
import json
from collections import Counter

path = "decisions.jsonl"
rows = []
try:
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
except FileNotFoundError:
    rows = []
counts = Counter(r.get("action", "?") for r in rows)
print(f"total={len(rows)} counts={dict(counts)}")
traps_blocked = sum(1 for r in rows if r.get("reason") in ("high-risk", "unsafe-state", "destructive-low-confidence"))
print(f"traps_blocked_by_policy={traps_blocked}")
print("note=cost per decision comes from Jev usage input_tokens, output is free")
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest -v`
Expected: PASS, all suites green including golden traps blocked to ask-human.

- [ ] **Step 5: Commit**

```bash
git add tests/test_golden.py tests/golden.json scripts/measure.py
git commit -m "test: add golden traps and measure script"
```
```
