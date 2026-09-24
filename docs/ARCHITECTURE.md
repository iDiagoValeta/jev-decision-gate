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
  → spawn pythonBin -m jev_gate.cli (timeout 25s default, max 30s,
        PYTHONPATH=src, minimal env)
      → build_state: curated brief + detail_sha256
      → build_questions: decision(choice) + safe(noul) + risk(score)
      → client.evaluate → Jev API (system_one)
      → decision.combine: pass through Jev's decision, no thresholds
      → stdout {action, reason, confidence, model, usage?}
  → plugin: allow→reply once, deny→reply reject,
            ask-human→silence, logged (no desktop alert — removed)
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
  → else ask-human, logged (pick no longer log-only)
```

`pythonBin` resolution: `options.pythonBin` → `JEV_GATE_PYTHON` → newest
mise install under `~/.local/share/mise/installs/python/*/bin/python3` →
`python3`. The spawn sets `PYTHONPATH=<repo>/src` so `typesafe_sdk`
works when the opencode service’s `/usr/bin/python3` lacks it.

Live autonomy check (non-interactive, against a running service):
`scripts/verify_autonomy.py` — see `docs/TROUBLESHOOTING.md`.

## Key decisions (ADRs, short)

- **`opencode run --auto` is out of scope — it bypasses the gate
  entirely, by design.** `--auto` is a client-side "auto-approve
  permissions not explicitly denied" behavior in opencode's own CLI; it
  does not wait for `permission.asked` subscribers, so it typically
  resolves a request before this plugin's reply (always at least one
  subprocess spawn plus an HTTP round trip) can land — including
  defeating the catastrophic-pattern kill-list, which replies in
  ~100ms with no network call and still loses. Confirmed live with a
  zero-risk repro (`terraform destroy`, `terraform` not installed):
  executed under `--auto`, correctly blocked (`executed: false`) via
  the raw session API with no `--auto`. No fix is possible from inside
  this plugin — there is no hook that fires before `--auto` commits.
  See `docs/TROUBLESHOOTING.md` and issue #21. Headless/autonomous
  sessions that need the gate's protection must go through the raw
  session API (`POST /api/session`, `POST /api/session/{id}/prompt`,
  poll `GET /api/session/{id}/message`) instead of `--auto`.
- **Reply to permissions via `opencode api POST`, never
  `ctx.permission.reply()`.** The SDK method was intermittently
  unreliable (`reply-failed: Permission request not found`) on
  permissions that were, live-verified, still pending server-side
  minutes later — never a timing race, despite an earlier same-day
  theory that it was (see `docs/TROUBLESHOOTING.md`, issue #15, for the
  full story of how that theory got falsified). `replyPermission` in
  `index.ts` shells out to `opencode api POST
  /api/session/{sessionID}/permission/{requestID}/reply`, mirroring
  `replyFormAnswer`'s already-reliable pattern for form answers, at all
  four sites that used to call the SDK method (catastrophic-reject,
  question-permission passthrough, main allow/deny, duplicate-event
  retry). Re-verified live: 17/17 successes under deliberately
  concurrent load that reliably reproduced the original failures.
- **Fail-open, never silent allow.** Every `except` maps to
  `ask-human/fail-open` with an `error_class` (and, since the
  concurrent-load session that found the "transport" bucket alone was
  undiagnosable, an `error_detail`). Rationale: a broken gate must cost
  a prompt, not a breach. There used to also be a best-effort desktop
  alert (`notify-send`/`zenity`) on this path; removed after it proved
  actively disruptive under real concurrent multi-session load (several
  fail-opens firing unattended dialogs with no one there to click
  them) — the log is the only signal now, by design, not an oversight.
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
- **Fence the untrusted parts of the brief, don't pretend they're
  trusted.** `OBJECTIVE` and `HALT.detail` are attacker-reachable
  (conversation text, file/command content). `build_objective_block`
  wraps both in a per-request random-token fence with an explicit
  "this is data" instruction, and neutralizes any accidental/forged
  match of the fence token inside the untrusted content itself, so a
  fake closing marker can't inject trailing `POLICY:`/`QUESTION:`
  lines. This is a partial mitigation, not a fix — Jev's judgment over
  the fenced content is still the only real defense against a
  sufficiently convincing adversarial payload. See `SECURITY.md`
  "Accepted risk: prompt injection into Jev's brief" for the full,
  explicitly-stated trade-off (found by an adversarial security
  review; previously an undocumented, implicit assumption).
- **Option labels are capped and redacted too, not just OBJECTIVE/
  detail.** A second adversarial pass found that `labelsFromFormField`
  (`index.ts`, question-tool multichoice options) fed Jev's `"pick"`
  criteria with attacker-reachable label text that had no length cap
  and no redaction, unlike `OBJECTIVE`/`HALT.detail`. Not a bypass —
  whatever Jev picks must still be one of the attacker's own
  pre-supplied options, checked independently on both the TS
  (`labels.includes`) and Python (`choice not in options`) sides — but
  an unbounded, unfenced injection/cost surface all the same. Each
  label is now redacted and capped at 200 chars (`normalizedLabel`);
  `valueForPick` re-derives the same normalization at lookup time
  (rather than assuming a positional mapping) so a truncated/redacted
  pick still round-trips to its real underlying value.
- **Form answers honor field types and visibility, not just
  multichoice picks (issues #55/#57).** In `handleFormAsked`, a
  `multiselect` field's reply value is an **array** of the picked
  option values (`{"answer":{"q0":["pizza"]}}`) rather than a string;
  `hidden`/`when` conditions gate each field against the answers
  already decided (`fieldVisible`, `eq`/`neq` compared with `===`; an
  unreferenced key ⇒ `eq` false / `neq` true), and a not-visible or
  unanswerable field (no options, non-multiselect type) is omitted
  from the reply — the server 400s on a reply that includes a field
  whose `when` isn't satisfied, so sending it is not optional. Every
  early exit from the field loop logs a distinct `reason`
  (`form-jev-not-allow`, `form-pick-not-offered`,
  `form-pick-ambiguous`, `form-unsupported-field`,
  `form-field-hidden`) with `fieldKey` instead of returning silently;
  any aborting reason leaves the form pending for the human, same as
  any other ask-human.
- **The event-subscription loop is sequential, by construction, not
  by oversight — documented as an accepted limitation, not fixed.**
  The same review traced `for await (const event of ctx.event.
  subscribe(...))` (`index.ts`) against `@opencode/plugin`'s actual
  iterator implementation and confirmed it's a plain pull-based async
  iterator: `await handleOne(...)` for one permission blocks the loop
  from even starting the next event (of any kind) until that gate
  round-trip finishes (up to `timeoutMs`, 25s default/30s max). Under
  concurrent load — the exact scenario this plugin's autonomy design
  targets — later simultaneous permissions queue behind earlier ones,
  each additionally exposed to the reply-window pressure issue #15
  was fixed for. This also means `inFlight`'s "concurrent duplicates
  await the same promise" branch is currently unreachable (only one
  requestID can occupy it at a time by construction) — not incorrect,
  just dead code a future maintainer could misread as live concurrency
  protection. Parallelizing event dispatch would touch the exact
  dedup/claim logic that caused issue #15/R52/R55/R57's duplicate-
  evaluation bugs, so it's being left as a known, named limitation for
  a dedicated change with its own review, not folded into this cycle's
  fixes. The unbounded growth of `resolved`/`endedSessions`/`formSeen`
  that the same review flagged *was* fixed here — a size cap
  (`capped()`, 2000 entries, clears rather than tracking per-entry
  age) — since that one was low-risk and additive, unlike parallelizing
  the loop.
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
