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
        out = {
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
        if "pick" in answers:
            out["pick"] = {"choice": answers["pick"]["choice"]}
        return out
    except Exception as exc:
        raise JevCallError(f"bad-response: {exc}") from exc
