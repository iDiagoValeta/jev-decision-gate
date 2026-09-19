# jev-decision-gate

Jev (TypeSafe AI) as the permission gate for OpenCode: routine tool
calls get approved automatically with calibrated confidence, anything
risky or uncertain falls back to your manual prompt.

## How it works

```
opencode v2 ──permission.asked──▶ plugin/ ──stdin/stdout──▶ jev_gate (Python) ──▶ Jev API
     ▲                                │ allow → reply once
     │                                │ deny → reply reject
     │                                │ ask-human → silence (you decide)
```

The plugin builds a gate event per halt: the session objective (taken
from your recent messages, so Jev judges in context), the halt kind
(`read`, `write`, `destructive`, `multichoice`), the tool and its
detail. Jev answers three parallel questions (allow/deny/ask-human,
is-this-safe, risk-score) and a pure threshold policy combines them.
Any error fail-opens to ask-human: a broken gate never silently allows.

Catastrophic shell patterns (`rm -rf /`, `mkfs`, fork bombs, ...) are
rejected instantly without calling Jev.

## Requirements

- OpenCode v2 (the v2 plugin hook; stable 1.x does not fire it)
- Python 3.10+ with `pip install typesafe-sdk`
- A TypeSafe API key (`console.typesafe.ai`)

## Quickstart

```jsonc
// opencode.jsonc (per project) — or your global config for all sessions
{
  "permissions": [{ "action": "shell", "resource": "*", "effect": "ask" }],
  "plugins": [
    {
      "package": "/absolute/path/to/jev-decision-gate/plugin/jev-decision-gate",
      "options": { "typesafeKey": "<TYPESAFE_API_KEY>" },
    },
  ],
}
```

All plugin options (`typesafeKey`, `logFile`, `gateDir`, `enabled`)
are documented in [plugin/README.md](plugin/README.md). Disable
anytime with `"enabled": false` or `JEV_GATE_ENABLED=0`.

## Safety model

| Threshold                | Value |
| ------------------------ | ----- |
| Confidence floor         | 0.50  |
| Read / write allow       | 0.60  |
| Destructive / other allow| 0.85  |

Unknown decision strings and unknown halt kinds are treated as
destructive. Every decision is appended to a JSONL log
(`decisions-plugin.jsonl` by default) with no secrets.

## Layout

- `plugin/` — v2 adapter (TypeScript, zero runtime deps)
- `src/jev_gate/` — gate: `schemas.py` (state/questions builders),
  `client.py` (Jev wrapper), `decision.py` (threshold policy),
  `cli.py` (stdin/stdout gate with fail-open)
- `tests/` — pytest suite plus `golden.json` traps
- `scripts/measure.py` — allowance / trap-blocked counts over the log
- `docs/` — design spec and plans

## Develop

```bash
python3 -m pytest -q
python3 scripts/measure.py
```
