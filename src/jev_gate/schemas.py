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
