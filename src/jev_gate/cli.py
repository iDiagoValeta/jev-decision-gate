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
