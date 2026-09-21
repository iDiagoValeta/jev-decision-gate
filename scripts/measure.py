#!/usr/bin/env python3
"""measure.py v2 — allowance / safety / latency / cost over v1+v2 logs.

Usage: python3 scripts/measure.py [--log PATH]... [--json] [--by-session]
       [--price-per-1k USD]  (cost = input_tokens * price / 1000)
Reads JEV_GATE_LOG env by default; tolerates corrupt lines and both
schema versions (action vs gateAction, elapsedMs vs duration_ms).
"""
import argparse
import json
import math
import os
import sys
from collections import Counter

TRAP_REASONS = {"catastrophic-pattern"}
DENY_REASONS = {"jev-deny"}
FAIL_OPEN = "fail-open"


def _safe_float(x, default=0.0):
    """float(x), rejecting non-numeric AND non-finite (NaN/Infinity).

    Round 8 review, live-verified: a JSON-valid-but-non-numeric
    elapsedMs string crashed the whole report (ValueError, uncaught);
    a NaN/Infinity elapsedMs didn't crash but silently poisoned
    p95/mean for the entire report with no warning, and made --json's
    own output invalid JSON (json.dumps emits bare NaN/Infinity
    tokens by default). Same bug class round 6 already fixed for
    decision.confidence in client.py, unreviewed here until now.
    """
    try:
        v = float(x)
    except (TypeError, ValueError):
        return default
    return v if math.isfinite(v) else default


def _safe_int(x, default=0):
    try:
        return int(x)
    except (TypeError, ValueError):
        return default


def load(paths):
    rows = []
    corrupt = 0
    for path in paths:
        try:
            with open(path, encoding="utf-8") as handle:
                for line in handle:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        parsed = json.loads(line)
                    except json.JSONDecodeError:
                        corrupt += 1
                        continue
                    # A line can be valid JSON and still not be a log row
                    # (a bare number/string/null/array) — round 8 review,
                    # live-verified this crashed main()'s first .get()
                    # call on it. Same "tolerates corrupt lines" bucket.
                    if not isinstance(parsed, dict):
                        corrupt += 1
                        continue
                    rows.append(parsed)
        except FileNotFoundError:
            pass
    return rows, corrupt


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--log", action="append", default=[])
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--by-session", action="store_true")
    ap.add_argument("--price-per-1k", type=float, default=0.0)
    args = ap.parse_args()
    paths = args.log or [os.environ.get("JEV_GATE_LOG", "decisions-plugin.jsonl"),
                         "decisions-plugin.jsonl", "decisions.jsonl"]
    # dedupe, keep order
    seen, uniq = set(), []
    for p in paths:
        if p not in seen:
            seen.add(p)
            uniq.append(p)
    rows, corrupt = load(uniq)
    actions = Counter((r.get("gateAction") or r.get("action") or "?") for r in rows)
    errcls = Counter(r.get("error_class", "-") for r in rows if r.get("reason") == FAIL_OPEN)
    total = len(rows)
    traps = sum(1 for r in rows if r.get("reason") in TRAP_REASONS or r.get("reason") in DENY_REASONS)
    failopen = sum(1 for r in rows if r.get("reason") == FAIL_OPEN)
    lat = sorted(_safe_float(r.get("elapsedMs", r.get("duration_ms", 0))) for r in rows)
    p95 = lat[min(len(lat) - 1, int(0.95 * len(lat)))] if lat else 0
    mean = sum(lat) / len(lat) if lat else 0
    tokens = sum(_safe_int((r.get("usage") or {}).get("input_tokens", 0)) for r in rows
                 if isinstance(r.get("usage"), dict))
    cost = tokens * args.price_per_1k / 1000.0
    out = {
        "total": total,
        "actions": dict(actions),
        "allow_rate": (actions.get("allow", 0) / total) if total else 0,
        "traps_blocked": traps,
        "fail_open": failopen,
        "fail_open_rate": (failopen / total) if total else 0,
        "error_classes": dict(errcls),
        "p95_elapsed_ms": p95,
        "mean_elapsed_ms": round(mean, 1),
        "input_tokens": tokens,
        "est_cost_usd": round(cost, 4),
        "corrupt_lines": corrupt,
    }
    if args.by_session:
        by = {}
        for r in rows:
            sid = r.get("sessionID") or "unknown"
            b = by.setdefault(sid, {"n": 0, "allow": 0, "fail_open": 0})
            b["n"] += 1
            if (r.get("gateAction") or r.get("action")) == "allow":
                b["allow"] += 1
            if r.get("reason") == FAIL_OPEN:
                b["fail_open"] += 1
        out["by_session"] = by
    if args.json:
        print(json.dumps(out, indent=2))
    else:
        print(f"total={total} actions={dict(actions)}")
        print(f"allow_rate={out['allow_rate']:.2f} traps_blocked={traps} "
              f"fail_open={failopen} ({out['fail_open_rate']:.2f}) errors={dict(errcls)}")
        print(f"p95_elapsed_ms={p95} mean={out['mean_elapsed_ms']} corrupt={corrupt}")
        print(f"input_tokens={tokens} est_cost_usd={out['est_cost_usd']}")
        if args.by_session:
            for sid, b in out["by_session"].items():
                # A lone UTF-16 surrogate in sessionID (round 8 review,
                # live-verified) crashes a raw print via stdout's utf-8
                # encoder — same bug class round 7 fixed for sha256_hex,
                # unreviewed here. errors="replace" for a display-only
                # truncated preview, not anything requiring fidelity.
                safe_sid = sid[:8].encode("utf-8", errors="replace").decode("utf-8")
                print(f"  session {safe_sid}: n={b['n']} allow={b['allow']} fail_open={b['fail_open']}")
        print("note=cost needs --price-per-1k and usage.input_tokens in log")


if __name__ == "__main__":
    sys.exit(main())
