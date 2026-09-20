# jev-decision-gate

Jev (TypeSafe AI) as the permission gate for OpenCode: routine tool
calls get approved automatically, anything Jev calls risky or
uncertain falls back to your manual prompt.

```
opencode v2 ──permission.asked──▶ plugin/ ──stdin/stdout──▶ jev_gate (Python) ──▶ Jev API
     ▲                                │ allow → reply once
     │                                │ deny → reply reject
     │                                │ ask-human → silence (you decide)
```

The plugin builds a curated brief per halt — objective, halt kind,
tool, redacted detail, risk hints — so Jev judges in context.
Jev answers three parallel questions (allow/deny/ask-human,
is-this-safe, risk-score); the `decision` answer alone wins, at any
confidence — safe/risk are recorded as evidence, not vetoes (see
"Safety model" below for why). Any error fail-opens to ask-human: a
broken gate never silently allows.

Catastrophic shell patterns (`rm -rf /`, pipe-to-shell, force-push,
`mkfs`, fork bombs, ...) are rejected instantly without calling Jev.

Agent questions to you (multichoice) are triaged too: Jev records a
**recommendation** (`pick` in the log, options numbered `1. 2. 3.`),
but the final choice is always yours — the v2 permission reply
carries no option field, so auto-answering is impossible by design.

## Requirements

- OpenCode on the `@opencode/plugin` line (`permission.asked` events;
  the older, more common `@opencode-ai/plugin` line does not fire it —
  see [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) if you're not
  sure which one you have)
- `"permission": "ask"` in your `opencode.json` (global or project) —
  under `"allow"` there's nothing for the gate to intercept
- Python 3.10+ with `pip install -e .` (pulls `typesafe-sdk`)
- Node 20+ for the plugin adapter
- A TypeSafe API key (`console.typesafe.ai`)

## Quickstart

```bash
git clone git@github.com:iDiagoValeta/jev-decision-gate.git
cd jev-decision-gate
./scripts/install.sh --project   # or --global for every session
export TYPESAFE_API_KEY="..."
python3 -m jev_gate.doctor
```

Or manually — see [plugin/README.md](plugin/README.md) for the full
options table (`typesafeKey`, `logFile`, `gateDir`, `enabled`,
`timeoutMs`). Disable anytime with `"enabled": false` or
`JEV_GATE_ENABLED=0`.

## Safety model

Jev decides — no confidence thresholds. Whatever Jev's `decision`
answer says wins: allow executes, deny blocks, ask-human falls back
to your manual prompt, at any confidence. The safe/risk answers are
recorded evidence, not vetoes.

What never executes: unknown decision strings (treated as ask-human),
any error (fail-open to ask-human), and catastrophic shell patterns
(rejected locally without calling Jev).

Every decision is appended to a JSONL log (v2 schema:
`at`, `sessionID`, `requestID`, `tool`, `kind`, `gateAction`,
`reason`, `confidence`, `model`, `pick`, `elapsedMs`,
`detail_sha256`) with no secrets, mode `0600`.

## Layout

- `plugin/` — v2 adapter (TypeScript, zero runtime deps besides `@opencode/plugin`)
- `src/jev_gate/` — gate: `schemas.py` (brief/redaction/questions),
  `client.py` (Jev wrapper), `decision.py` (decision combine, no thresholds),
  `cli.py` (stdin/stdout gate with fail-open), `doctor.py`
- `tests/` — pytest suite plus `golden.json` traps
- `scripts/` — `install.sh`, `uninstall.sh`, `doctor.py` shim, `measure.py` v2
- `docs/` — [ARCHITECTURE.md](docs/ARCHITECTURE.md), [TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md)

## Develop

```bash
python3 -m pytest -q
python3 scripts/measure.py --by-session
python3 -m jev_gate.doctor
```

See [CONTRIBUTING.md](CONTRIBUTING.md), [CHANGELOG.md](CHANGELOG.md),
[SECURITY.md](SECURITY.md).
