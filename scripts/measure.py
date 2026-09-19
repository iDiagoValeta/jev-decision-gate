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
latencies = [float(r["duration_ms"]) for r in rows if isinstance(r.get("duration_ms"), (int, float))]
if latencies:
    ordered = sorted(latencies)
    idx = min(len(ordered) - 1, int(0.95 * len(ordered)))
    print(f"p95_latency_ms={ordered[idx]}")
else:
    print("p95_latency_ms=unknown (no duration_ms in log; needs real calls)")
print("note=cost per decision comes from Jev usage input_tokens, output is free")
