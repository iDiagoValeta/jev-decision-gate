import json
import os
import sys
from datetime import datetime, timezone

from . import client as client_mod
from . import decision as decision_mod
from . import schemas as schemas_mod


def _classify_error(exc):
    name = type(exc).__name__
    msg = str(exc) if exc is not None else ""
    if "missing-api-key" in msg:
        return "missing-key"
    if msg.startswith("bad-response"):
        return "bad-response"
    if msg.startswith("missing-sdk"):
        return "transport"
    if name == "JevCallError":
        return "transport"
    return "exception"


def decide_event(event, evaluate_fn, _error_box=None):
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
            options = halt.get("options") or []
            choice = None
            try:
                choice = result.get("pick", {}).get("choice")
            except Exception:
                choice = None
            if choice not in options:
                if _error_box is not None:
                    _error_box["error_class"] = "bad-response"
                return {
                    "action": "ask-human",
                    "reason": "fail-open",
                    "pick": None,
                    "confidence": 0.0,
                    "model": None,
                }
            pick = choice
        return {
            "action": combined["action"],
            "reason": combined["reason"],
            "pick": pick,
            "confidence": float(result["decision"]["confidence"]),
            "model": result.get("model"),
        }
    except Exception as exc:
        if _error_box is not None:
            _error_box["error_class"] = _classify_error(exc)
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

    error_box = {}
    out = decide_event(event if event else {"objective": "", "halt": {"kind": "write"}}, real_evaluate, error_box)
    log_path = os.environ.get("JEV_GATE_LOG", "decisions.jsonl")
    try:
        with open(log_path, "a", encoding="utf-8") as handle:
            entry = {
                "at": datetime.now(timezone.utc).isoformat(),
                "model": out.get("model"),
                "action": out.get("action"),
                "reason": out.get("reason"),
                "confidence": out.get("confidence"),
            }
            if out.get("reason") == "fail-open" and error_box.get("error_class"):
                entry["error_class"] = error_box["error_class"]
            handle.write(json.dumps(entry) + "\n")
    except Exception:
        pass
    sys.stdout.write(json.dumps(out))


if __name__ == "__main__":
    main()
