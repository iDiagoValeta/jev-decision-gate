# Architecture

## Flow

Requires `"permission": "ask"` in opencode's config (global or
project) — under `"allow"`, opencode 2.0.11 never emits
`permission.asked` at all, so there is nothing for the gate to
intercept. See `docs/TROUBLESHOOTING.md`.

```
permission.asked (opencode v2)
  → claim requestID (exclusive marker, cross-instance/cross-process) — lose it, do nothing
  → catastrophic check (local regex over normalized command, no network)
  → kindFor(action, resources): read | write | destructive | multichoice
  → objectiveFor(sessionID): recent conversation, both roles, redacted,
                              ≤4000 chars default (options.objectiveChars /
                              JEV_GATE_OBJECTIVE_CHARS)
  → gateEvent { objective, halt {kind,tool,detail≤4000 redacted,options?},
                context {sessionID,requestID,risk_hints}, policy }
  → spawn python3 -m jev_gate.cli (timeout 15s default, max 30s, minimal env)
      → build_state: curated brief + detail_sha256
      → build_questions: decision(choice) + safe(noul) + risk(score) [+ pick]
      → client.evaluate → Jev API (system_one)
      → decision.combine: pass through Jev's decision, no thresholds
      → stdout {action, reason, pick?, confidence, model, usage?}
  → plugin: allow→reply once, deny→reply reject, ask-human→silence
  → both sides append v2 JSONL (0600, no secrets)
```

## Key decisions (ADRs, short)

- **Fail-open, never silent allow.** Every `except` maps to
  `ask-human/fail-open` with an `error_class`. Rationale: a broken
  gate must cost a prompt, not a breach.
- **Two writers, one schema.** Plugin and CLI each log (the CLI sees
  the Jev internals, the plugin sees session/request IDs). Schema v2
  unifies field names so `measure.py` reads both.
- **`multichoice` never replies** — but this is a harmless
  simplification, not a fix. The reply always arrives too late for
  this tool regardless (client commits to its own confirmation UI
  before Jev's round-trip can land), so skipping it costs nothing.
  **It does NOT fix the question-tool hang after the human picks an
  option** — ruled out live: hangs the same with or without the reply
  attempted. Root cause still unknown; three fix attempts have failed.
  See `docs/TROUBLESHOOTING.md` "Question dialog hangs" before trying a
  fourth. `pick` stays a logged recommendation only — `reply()` has no
  option field, it was never going to answer for the human. See
  `docs/TROUBLESHOOTING.md` for the evidence and repro.
- **Redact before send.** Secrets never leave the box: redaction
  runs in TS (before spawn) and Python (before Jev call); logs store
  `detail_sha256`, not detail.
- **Jev decides, no thresholds.** The winning action is whatever
  Jev's `decision` answer says, at any confidence. Safe/risk answers
  are evidence, not vetoes. Unknown strings and errors still degrade
  to ask-human; catastrophic patterns never reach Jev.
- **One evaluation per request, claimed before calling Jev.** The
  server may emit the same permission request more than once while
  pending, AND `setup()` runs more than once per opencode process
  (confirmed: same `pid`, different `inst` in the log) — two independent
  plugin instances can receive the same event. An exclusive marker file
  (`.jev-gate-replied/<requestID>`) is claimed at the top of `handleOne`,
  before any Jev call: the loser skips entirely (no Jev call, no reply
  attempt), the winner evaluates and replies once. Within one instance,
  in-flight sharing + a resolved cache also dedupe cheaply; late
  duplicates log `duplicate-suppressed`.
- **Single-writer log.** The plugin logs every decision; the Python
  gate stays silent when spawned by the plugin (`JEV_GATE_CLI_LOG=0`)
  and logs only in standalone use.
- **Bounded multi-turn context, not unbounded history.** `objectiveFor`
  sends recent conversation turns from both the user and the assistant
  (assistant text only, tool-call payloads are skipped), newest-first
  until a char budget is hit, so Jev can judge whether a halt matches
  what the agent has actually been doing — not just the human's last
  message. The budget is bounded by default (`objectiveChars` /
  `JEV_GATE_OBJECTIVE_CHARS`, default 4000) because an unbounded full
  transcript would make every single permission check's cost and
  latency scale with session length; raise it per-project if that
  trade-off is wrong for your session sizes.

## Files

| File | Owns |
| ---- | ---- |
| `plugin/jev-decision-gate/index.ts` | hook, catastrophic, kind, objective, spawn, log |
| `src/jev_gate/schemas.py` | brief, redaction, questions |
| `src/jev_gate/client.py` | SDK wrapper, usage passthrough |
| `src/jev_gate/decision.py` | decision combine, no thresholds (pure, fully tested) |
| `src/jev_gate/cli.py` | stdin/stdout, v2 log, fail-open map |
| `src/jev_gate/doctor.py` | diagnostics |
| `scripts/measure.py` | rates, p95, cost, by-session |
