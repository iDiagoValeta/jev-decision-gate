# src/jev_gate/decision.py
"""Threshold policy combining Jev's three parallel answers.

Fail-open by construction: anything unknown, uncertain, unsafe or
high-risk degrades to ask-human. Only an explicit confident allow
passes.
"""

READ_ALLOW = 0.6
WRITE_ALLOW = 0.6
MULTICHOICE_ALLOW = 0.7
DESTRUCTIVE_ALLOW = 0.85
CONF_FLOOR = 0.5
SAFE_MIN = 0.3
RISK_MAX = 1.5


def combine(decision_choice, decision_confidence, safe_noul, risk_score, halt_kind):
    if decision_choice not in ("allow", "deny", "ask-human"):
        return {"action": "ask-human", "reason": "unknown-choice"}
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
    if halt_kind == "write" and decision_confidence < WRITE_ALLOW:
        return {"action": "ask-human", "reason": "write-low-confidence"}
    if halt_kind == "multichoice" and decision_confidence < MULTICHOICE_ALLOW:
        return {"action": "ask-human", "reason": "multichoice-low-confidence"}
    if halt_kind not in ("read", "write", "multichoice") and decision_confidence < DESTRUCTIVE_ALLOW:
        return {"action": "ask-human", "reason": "destructive-low-confidence"}
    return {"action": "allow", "reason": "jev-allow"}
