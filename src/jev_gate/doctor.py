"""Gate doctor: diagnose install without leaking secrets."""

import importlib.util
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path


def check(name, ok, hint=""):
    print(f"{'OK  ' if ok else 'FAIL'}  {name}" + (f" — {hint}" if hint and not ok else ""))
    return ok


_REPO = Path(__file__).resolve().parents[2]


def plugin_log_path():
    """The log the plugin writes: JEV_GATE_LOG, else `logFile` from the
    opencode config (measure.py's lookup), else `<repo>/decisions-plugin.jsonl`."""
    env = os.environ.get("JEV_GATE_LOG")
    if env:
        return env
    cfg = None
    try:
        spec = importlib.util.spec_from_file_location("jev_measure", _REPO / "scripts" / "measure.py")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        cfg = mod._config_logfile()
    except Exception:
        cfg = None
    return cfg or str(_REPO / "decisions-plugin.jsonl")


def _writable(path):
    """Checks without creating the file: a stray empty log is a side effect."""
    p = Path(path)
    if p.exists():
        return os.access(p, os.W_OK)
    return p.parent.is_dir() and os.access(p.parent, os.W_OK)


def main():
    ok_all = True
    ok_all &= check("python>=3.10", sys.version_info >= (3, 10), sys.version)
    ok_all &= check("typesafe_sdk importable", importlib.util.find_spec("typesafe_sdk") is not None,
                    "pip install typesafe-sdk")
    ok_all &= check("jev_gate.cli importable", importlib.util.find_spec("jev_gate.cli") is not None,
                    "pip install -e . (run from repo root)")
    ok_all &= check("node present", shutil.which("node") is not None, "install nodejs")
    # v2 is often installed under a different command name than stable
    # (e.g. `opencode-v2` alongside a v1 `opencode`) while it is beta.
    # Check both; report whichever one is actually v2, since the gate
    # only fires under v2's `permission.asked` event.
    found_v2 = False
    seen = []
    for cmd in ("opencode-v2", "opencode"):
        path = shutil.which(cmd)
        if not path:
            continue
        try:
            out = subprocess.run([cmd, "--version"], capture_output=True, text=True, timeout=10)
            raw = (out.stdout + out.stderr).strip()
            ver = raw.splitlines()[0] if raw else "unknown"
        except Exception:
            ver = "unknown"
        is_v2 = ver.startswith("2") or "v2" in ver
        seen.append(f"{cmd}={ver}{' (v2)' if is_v2 else ''}")
        found_v2 = found_v2 or is_v2
    if seen:
        ok_all &= check(f"opencode v2 present ({', '.join(seen)})", found_v2,
                        "gate sleeps on stable 1.x by design; a v1 `opencode` alongside v2 is fine")
    else:
        ok_all &= check("opencode on PATH", False, "install opencode v2 (try `opencode-v2` or `opencode`)")
    key = os.environ.get("TYPESAFE_API_KEY", "")
    ok_all &= check("TYPESAFE_API_KEY set", bool(key), "export TYPESAFE_API_KEY=... (value never printed)")
    log = plugin_log_path()
    ok_all &= check(f"log writable ({log})", _writable(log), "fix permissions or set logFile / JEV_GATE_LOG")

    # synthetic round-trip through decide_event (no network)
    try:
        from jev_gate.cli import decide_event

        def fake(state, questions):
            assert state.get("halt", {}).get("detail") == "Read x", "state missing structured halt"
            return {"decision": {"choice": "allow", "confidence": 0.9},
                    "safe": {"noul": 0.9}, "risk": {"score": 0.1, "confidence": 0.8},
                    "model": "doctor"}
        out = decide_event({"objective": "doctor check",
                            "halt": {"kind": "read", "tool": "read", "detail": "Read x"},
                            "context": {}, "policy": {}}, fake)
        ok_all &= check("gate round-trip", out["action"] == "allow", json.dumps(out)[:120])
    except Exception as exc:
        ok_all &= check("gate round-trip", False, str(exc)[:120])

    print("doctor: " + ("ALL OK" if ok_all else "ISSUES FOUND"))
    raise SystemExit(0 if ok_all else 1)


if __name__ == "__main__":
    main()
