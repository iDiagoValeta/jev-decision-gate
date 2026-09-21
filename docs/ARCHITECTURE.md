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
  → if action === "question":
        permission.reply once (passthrough-allow)
        NO session.context, NO Jev on this path
        log reason=question-permission-passthrough
        (answering happens via form API — see below)
  → else kindFor(action, resources):
        read | write | destructive
        (covers documented keys: read, edit/write/apply_patch, glob,
         grep, bash, task, skill, lsp, webfetch, websearch,
         external_directory, doom_loop → destructive; unknown → ask-human)
  → objectiveFor(sessionID): recent conversation, both roles, redacted,
                              ≤4000 chars default (options.objectiveChars /
                              JEV_GATE_OBJECTIVE_CHARS)
  → gateEvent { objective, halt {kind,tool,detail≤4000 redacted},
                context {sessionID,requestID,risk_hints}, policy }
  → spawn pythonBin -m jev_gate.cli (timeout 15s default, max 30s,
        PYTHONPATH=src, minimal env)
      → build_state: curated brief + detail_sha256
      → build_questions: decision(choice) + safe(noul) + risk(score)
      → client.evaluate → Jev API (system_one)
      → decision.combine: pass through Jev's decision, no thresholds
      → stdout {action, reason, confidence, model, usage?}
  → plugin: allow→reply once, deny→reply reject,
            ask-human→silence + notify-send critical + zenity popup
  → both sides append v2 JSONL (0600, no secrets)

question tool → form (metadata.kind=question), listed at GET /api/form
  → plugin polls /api/form (also listens form.created /
    legacy question.v2.asked / question.asked)
  → claim form:<formID> (same exclusive-marker pattern)
  → objectiveFor (bounded; failures fall back to a short default)
  → for each form field with options: runGate as multichoice (+ pick)
  → allow+valid pick → POST /api/session/{sessionID}/form/{formID}/reply
                        body {"answer":{"q0":"<pick>", ...}}
     log phase=form-answer then reason=question-answered
  → else ask-human + desktop alert (pick no longer log-only)
```

`pythonBin` resolution: `options.pythonBin` → `JEV_GATE_PYTHON` → newest
mise install under `~/.local/share/mise/installs/python/*/bin/python3` →
`python3`. The spawn sets `PYTHONPATH=<repo>/src` so `typesafe_sdk`
works when the opencode service’s `/usr/bin/python3` lacks it.

Live autonomy check (non-interactive, against a running service):
`scripts/verify_autonomy.py` — see `docs/TROUBLESHOOTING.md`.

## Key decisions (ADRs, short)

- **Known gap: `ctx.permission.reply()` races a short server-side
  window.** Ordinary (non-question) replies land ~800ms+ after the
  halt (Jev's real API latency); under load that can miss whatever
  window opencode keeps a pending permission open for, and the reply
  fails (`reply-failed`) with the tool call left hanging rather than
  denied. The question/form path avoids this (a different endpoint,
  `POST .../form/{formID}/reply`, tolerates the same latency fine).
  Mitigated, not closed: `handleOne` now spawns the Python gate
  (`spawnGate`) before `objectiveFor`'s RPC instead of after, so the
  subprocess cold-starts in parallel with it instead of serially
  after it, and every `reply-failed` also fires the desktop alert
  (previously silent beyond a log line). The `Permission` schema has
  no TTL/duration field and `Reply` is exactly `"once" | "always" |
  "reject"` — there's no protocol-level way to ask for more time, so
  the race itself isn't closeable from the plugin side. See
  `docs/TROUBLESHOOTING.md` "Ordinary permission replies can silently
  miss the window" (issue #15) for the measurements and what a real
  fix would require.
- **Fail-open, never silent allow.** Every `except` maps to
  `ask-human/fail-open` with an `error_class`. Rationale: a broken
  gate must cost a prompt, not a breach. Ask-human (and fail-open)
  also triggers a best-effort desktop alert (`notify-send -u critical`
  plus `zenity --warning`) so the operator notices without watching
  the TUI.
- **Two writers, one schema.** Plugin and CLI each log (the CLI sees
  the Jev internals, the plugin sees session/request IDs). Schema v2
  unifies field names so `measure.py` reads both.
- **Two-phase question handling (form API on 2.0.x).** Agent questions
  are split across permission unlock and form answer:
  1. `permission.asked` with `action === "question"` — passthrough
     allow via `permission.reply({ decision: "once" })` with **no**
     `ctx.session.context` and **no** Jev call. Mid-flight
     `session.context` on this path was implicated (not proven) in
     the post-pick hang; the permission phase only unlocks the tool.
  2. Question tool opens a **form** (`metadata.kind=question`). The
     plugin discovers it via `GET /api/form` polling (and
     `form.created` / legacy question events), Jev returns a `pick`,
     and the plugin submits
     `POST /api/session/{sessionID}/form/{formID}/reply` with
     `{"answer":{"q0":"<pick>"}}`. This closes the old “pick is
     log-only” model (`permission.reply` has no option field and
     cannot answer for the human). Earlier docs that said
     `question.v2.asked` / `/api/question` were wrong for 2.0.11 —
     those event names may still appear as legacy listeners, but the
     live surface is the form API.
  Live-verified on 2.0.11: form reply unblocks the question tool and
  the agent continued (`ELEGIDO=pizza`, idle succeeded). That is **not**
  a claim that every hang case is fixed. Historical failed fixes and
  diagnostics live in `docs/TROUBLESHOOTING.md` "Question dialog hangs".
- **`kindFor` covers documented OpenCode permission keys.** Mapping
  follows https://opencode.ai/docs/permissions/: read-class
  (`read`, `glob`, `grep`, `external_directory`, `lsp`, `skill`, …),
  write-class (`edit` / `write` / `apply_patch`, `bash`, `task`,
  `webfetch`, `websearch`, …), `doom_loop` → destructive, `question`
  → multichoice (permission path only; see above). Anything else
  fail-opens to ask-human with an alert.
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
  attempt), the winner evaluates and replies once. Form answers use the
  same pattern with a `form:`-prefixed claim key. Within one
  instance, in-flight sharing + a resolved cache also dedupe cheaply;
  late duplicates log `duplicate-suppressed`.
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
  trade-off is wrong for your session sizes. The form-answer path
  uses a tighter budget (and tolerates `objectiveFor` failure) so a
  stuck context call does not block answering.

## Files

| File | Owns |
| ---- | ---- |
| `plugin/jev-decision-gate/index.ts` | hook, catastrophic, kind, objective, form API poll/reply, human alert, spawn (`pythonBin`/mise/`PYTHONPATH`), log |
| `src/jev_gate/schemas.py` | brief, redaction, questions |
| `src/jev_gate/client.py` | SDK wrapper, usage passthrough |
| `src/jev_gate/decision.py` | decision combine, no thresholds (pure, fully tested) |
| `src/jev_gate/cli.py` | stdin/stdout, v2 log, fail-open map |
| `src/jev_gate/doctor.py` | diagnostics |
| `scripts/measure.py` | rates, p95, cost, by-session |
| `scripts/verify_autonomy.py` | live non-interactive autonomy check |
