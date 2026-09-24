# src/jev_gate/client.py
"""Thin wrapper around the TypeSafe SDK with error mapping."""

import math


class JevCallError(Exception):
    pass


def _finite_float(x):
    """float(x), but reject NaN/Infinity too.

    Neither the SDK's pydantic models nor Python's own
    float()/json.loads() reject a non-finite confidence —
    json.dumps(float("nan")) emits a bare `NaN` token, which is invalid
    JSON (RFC 8259) and breaks the TS side's JSON.parse of the gate's
    stdout, turning a value decision.combine() doesn't even use for
    branching (see decision.py, "no thresholds") into a crash-adjacent
    failure downstream instead of a clean bad-response/ask-human.
    """
    v = float(x)
    if not math.isfinite(v):
        raise ValueError(f"non-finite value: {v!r}")
    return v


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
            out = {"model": model_name, "answers": norm}
            usage = getattr(result, "usage", None)
            if usage is None and isinstance(result, dict):
                usage = result.get("usage")
            if usage is not None:
                try:
                    tokens = usage.get("input_tokens") if isinstance(usage, dict) else getattr(usage, "input_tokens", None)
                    if tokens is not None:
                        out["usage"] = {"input_tokens": int(tokens)}
                except Exception:
                    pass
            return out
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
        out = {
            "decision": {
                "choice": answers["decision"]["choice"],
                "confidence": _finite_float(answers["decision"]["confidence"]),
            },
            "safe": {"noul": _finite_float(answers["safe"]["noul"])},
            "risk": {
                "score": _finite_float(answers["risk"]["score"]),
                "confidence": _finite_float(answers["risk"]["confidence"]),
            },
            "model": raw.get("model", model),
        }
        if "pick" in answers:
            out["pick"] = {"choice": answers["pick"]["choice"]}
        if "usage" in raw:
            out["usage"] = raw["usage"]
        return out
    except Exception as exc:
        raise JevCallError(f"bad-response: {exc}") from exc
