# Architecture

## Flow

```
permission.asked (opencode v2)
  → catastrophic check (local regex over normalized command, no network)
  → kindFor(action, resources): read | write | destructive | multichoice
  → objectiveFor(sessionID): last user messages, redacted, ≤500 chars
  → gateEvent { objective, halt {kind,tool,detail≤4000 redacted,options?},
                context {sessionID,requestID,risk_hints}, policy }
  → spawn python3 -m jev_gate.cli (timeout 15s default, max 30s, minimal env)
      → build_state: curated brief + detail_sha256
      → build_questions: decision(choice) + safe(noul) + risk(score) [+ pick]
      → client.evaluate → Jev API (system_one)
      → decision.combine: thresholds per kind
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
- **Recommend, don't auto-answer, multichoice.** v2 `reply` has no
  option field; `pick` is a logged recommendation with numbered
  options for the human.
- **Redact before send.** Secrets never leave the box: redaction
  runs in TS (before spawn) and Python (before Jev call); logs store
  `detail_sha256`, not detail.
- **Jev decides, no thresholds.** The winning action is whatever
  Jev's `decision` answer says, at any confidence. Safe/risk answers
  are evidence, not vetoes. Unknown strings and errors still degrade
  to ask-human; catastrophic patterns never reach Jev.
- **One evaluation per request.** The server may emit the same
  permission request several times while pending. The plugin dedupes
  by requestID (in-flight sharing + resolved cache): one Jev call,
  one reply, late duplicates logged as `duplicate-suppressed`.
- **Single-writer log.** The plugin logs every decision; the Python
  gate stays silent when spawned by the plugin (`JEV_GATE_CLI_LOG=0`)
  and logs only in standalone use.

## Files

| File | Owns |
| ---- | ---- |
| `plugin/jev-decision-gate/index.ts` | hook, catastrophic, kind, objective, spawn, log |
| `src/jev_gate/schemas.py` | brief, redaction, questions |
| `src/jev_gate/client.py` | SDK wrapper, usage passthrough |
| `src/jev_gate/decision.py` | threshold combine (pure, fully tested) |
| `src/jev_gate/cli.py` | stdin/stdout, v2 log, fail-open map |
| `src/jev_gate/doctor.py` | diagnostics |
| `scripts/measure.py` | rates, p95, cost, by-session |
