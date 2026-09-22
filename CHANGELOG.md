# Changelog

All notable changes to this project are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
versioning follows [SemVer](https://semver.org/).

## [Unreleased]

### Fixed
- **`listPendingForms` and `postApiReply` had the same missing-SIGKILL-backstop
  gap round 13 fixed in `spawnGate` — that audit only covered `spawnGate`
  itself.** Found by a 14th adversarial review round, live-verified: a
  hung `opencode` CLI that ignores SIGTERM leaked indefinitely through
  both call sites. `listPendingForms` runs on every 750ms poll tick with
  no backpressure, so a single hang leaks one orphaned process per tick;
  `postApiReply` backs every permission/form reply. Fixed by giving both
  the same 2s SIGKILL escalation `spawnGate` already has. New regression
  test (`listPendingForms`, whose 5s timeout is faster to exercise than
  `postApiReply`'s 10s) spawns a real SIGTERM-ignoring child and confirms
  it's dead within the backstop window; `postApiReply`'s identical fix
  was verified manually.
- **The event-stream form path (`form.created`/`question.*.asked`) could
  silently and permanently drop a form whose id lived only at the outer
  event payload, not inside the nested form object.** Same round.
  `handleFormAsked` re-derives its own `formID` from the object it's
  handed (`.id` alone, no further fallback), but the event-stream path
  already falls back to the outer payload's `.id` for its own `formSeen`
  tracking (`fid = form.id ?? payload.id`) — it just never carried that
  resolution into the object passed to `handleFormAsked`. A form shaped
  that way hit `handleFormAsked`'s own missing-ids early return: nothing
  ever got claimed on disk (`claimReply` never ran), while `formSeen` was
  already marked, permanently foreclosing the poll path's own retry for a
  form nothing had actually processed. Fixed by handing `handleFormAsked`
  a form object whose `.id` already matches the resolved `fid`. Also
  mirrored the poll path's own `formSeen` cleanup-on-failure in the
  event-stream path's catch, for consistency (a narrower, mostly
  defensive fix on its own — `handleFormAsked`'s internal fail-open catch
  swallows nearly every other failure without rejecting, so this rarely
  fires today, but nothing currently guarantees it never will).
  Both new regression tests fail against the pre-fix code and pass
  against the fix. 41 TS tests now (was 39).

### Fixed
- **`spawnGate`'s `cancel()` had no SIGKILL backstop, unlike the timeout
  path a few lines above it in the same function — a child that ignores
  or misses SIGTERM leaked forever.** Found by a 13th adversarial review
  round, live-verified: a child process that installs its own SIGTERM
  handler stayed alive at least 8s after `cancel()` (called from
  `handleOne` when `objectiveFor` detects the session ended mid-flight)
  with nothing left anywhere to retry killing it — every other exit path
  in `spawnGate` already had this backstop except this one. Fixed by
  giving `cancel()` the same 2s SIGKILL escalation the timeout path uses.
  New regression test spawns a real SIGTERM-ignoring child and confirms
  it's dead within the backstop window; fails pre-fix (still alive at
  8.5s), passes post-fix (~2.5s). 39 TS tests now (was 38).
- **`install.sh`/`uninstall.sh` crashed with a raw Python traceback if
  `opencode.jsonc` already had comments or trailing commas** — the exact
  case that extension's own name invites, and the one real reason to use
  `.jsonc` over `.json`. `set -euo pipefail` then aborted the whole
  script: for `install.sh`, after the pip/npm installs had already run;
  for `uninstall.sh`, after the `.bak` backup was made but before
  anything else (log purge, pip uninstall) could run, with no indication
  to the user whether the plugin was actually removed. Fixed by catching
  `json.JSONDecodeError` specifically and printing a clear, actionable
  message (the exact block to add/remove by hand) instead of a bare
  traceback — this doesn't attempt to parse JSONC, which would risk
  silently mis-editing a config with comments the user cares about; it
  fails cleanly instead. New regression test for `uninstall.sh` (real
  subprocess, no side effects); `install.sh`'s identical fix was verified
  manually rather than by an automated test, since it also runs a real
  `pip install`/`npm install` first — not something to trigger from every
  `pytest` run. 60 Python tests now (was 59, new file
  `tests/test_uninstall_sh.py`).

### Fixed
- **The on-disk reply-marker directory (`.jev-gate-replied/`) was only
  pruned once, at `setup()` startup — a long-running opencode host
  process (days/weeks, `setup()` never re-invoked) accumulated one marker
  file per permission/form forever.** Found by a 12th adversarial review
  round, live-verified: 5000 `claimReply` calls produced 5000 unpruned
  files. Same bug class already fixed for the in-memory collections
  (`resolved`/`endedSessions`/`formSeen`, via `capped()`); this was its
  on-disk sibling, left out of that fix. Fixed by giving `pruneReplied` its
  own `setInterval` (1h cadence, matching its own `maxAgeMs` default),
  mirroring the existing form-poll timer, cleared on teardown alongside it.
  New regression test asserts `setup()` registers 2 intervals and teardown
  clears both — fails pre-fix (1 interval), passes post-fix (2).
  38 TS tests now (was 37).
- **`scripts/measure.py --by-session` (plain-text mode) crashed with
  `TypeError: 'int' object is not subscriptable` if a log row's
  `sessionID` was numeric instead of a string.** Found by the same round.
  `sid[:8]` assumed `sessionID` was always a string; `--json` mode is
  unaffected (`json.dumps` coerces non-string dict keys itself), but the
  text-mode preview truncation crashed on any non-string, truthy
  `sessionID`. Fixed by coercing `sid` to `str` before slicing. New
  regression test, same revert-and-confirm-fails discipline.
  59 Python tests now (was 58).

### Fixed
- **Two ReDoS (algorithmic-complexity) bugs could freeze the whole
  opencode host for tens of seconds on realistic-sized input, before Jev
  is ever called.** Found and live-verified by an 11th adversarial review
  round, independently reproduced and extended. `isCatastrophic`'s
  kill-list regex for `rm -rf <target>` uses `.*`/`(\S*\s+)*` before
  searching for a real target; on a long string with no target present,
  every occurrence of "rm -rf" forces its own O(remaining-length)
  backtrack search, making the whole check O(n^2) — live-verified: ~1.6MB
  of `rm -rf junkword...` froze the event loop for ~19s. Follow-up
  scanning found the same `.* ` + literal-search shape in at least 10
  more of the 23-pattern kill list (dd, find, curl, wget, base64,
  powershell, git push, kubectl delete, aws s3 rm), all reachable the
  same way. Separately, `redactSecrets`'s `scheme://user:pass@host` regex
  has an unbounded scheme-prefix repetition, so a long string with no
  `://` anywhere forces the same kind of O(n^2) backtracking; reachable
  via `labelsFromFormField` on a single long multichoice option *before*
  its own 200-char truncation applies (live-verified: 100k chars took
  6.3s). The identical regex shape exists in Python's `schemas.py`
  (`build_objective_block`), where the standalone `python3 -m
  jev_gate.cli` entry point has no length bound on `objective` at all —
  a 5,000,000-char payload via stdin consumed 100% CPU for over 2.5
  minutes.

  Fixed two ways, chosen to close all discovered (and any not-yet-found)
  instances of the same shape rather than patch each of the 11+ affected
  regexes individually: `isCatastrophic` now bounds its input to the
  same 4000 chars Jev's own `detail` field already sees
  (`rawDetail = joined.slice(0, 4000)`), so this doesn't reduce real
  detection — nothing past that point is evaluated by either layer
  today. The `scheme://user:pass@` regex (both TS and Python) now bounds
  its scheme-prefix repetition to 20 characters (real schemes are a
  handful of characters), a strict O(n^2) -> O(n) fix with zero
  matching-behavior change, verified against realistic connection
  strings (postgresql, mongodb(+srv), mysql, redis, amqp, https, sftp).

  4 new regression tests (TS: adversarial-input timing bounds for both
  `isCatastrophic` and `redactSecrets`/`labelsFromFormField`, plus a test
  documenting the length-cap boundary as intentional; Python: the same
  timing-bound test for `redact_secrets`), each confirmed to fail
  against the pre-fix code (14.9s+ and 10.4s respectively) and pass
  against the fix (under 15ms).
  37 TS tests now (was 33), 58 Python tests now (was 57).

### Fixed
- **`handleOne`: a synchronous `spawn()` throw silently blackholed the
  permission — no reply, no log, no alert, and blocked all future
  retries for that requestID.** Found and live-verified by a 10th
  adversarial review round. `spawnGate(options)` was called *outside*
  `handleOne`'s own `try` block. `child_process.spawn()` throws
  **synchronously**, not via a rejected promise, when an env value
  derived from `options` is invalid — e.g. a NUL byte embedded in a
  malformed `typesafeKey`/`logFile`/`gateDir` in the plugin config
  (legal inside a JSON string as a unicode escape, plausible from a
  corrupted secrets pipeline). That throw propagated out of
  `handleOne` entirely, past every `log()`/`alertHuman()` call in the
  function, caught only by `setup()`'s bare event-loop `catch {}` —
  which logs nothing, alerts no one, and records a false
  `repliedOk: true`, so a later duplicate `permission.asked` for the
  same requestID never retries either (`claimReply` had already
  claimed it). Strictly worse than every other fail-open path in this
  file, all of which were built specifically to never fail silently.
  Fixed by moving `spawnGate` inside the try block — live-verified the
  fix routes this through the existing `fail-open`/`alertHuman` path
  instead, and confirmed the new regression test fails against the
  pre-fix code and passes against the fix.
  33 TS tests now (was 32).

### Verified clean (round 10, live-execution)
- `spawnGate`/`runGate` against genuinely malformed Python subprocess
  stdout: truncated JSON, two concatenated JSON objects on one line,
  raw binary garbage, output arriving just under the timeout boundary
  — all reject/resolve cleanly, no crashes.
- A write to `child.stdin` after the gate subprocess has already been
  SIGKILLed by the timeout escalation — silently no-ops on this Node
  version, doesn't crash (a plausible sibling to round 6's CRITICAL
  bug, checked directly and found not to reproduce).
- `isEnabled`/`repoRoot`/`apiKeyOf`/`timeoutMsOf`/`objectiveBudgetOf`/
  `pythonBin`/`logFileOf` against ~35 malformed/extreme `options`
  shapes (NaN, ±Infinity, wrong types, embedded NUL bytes, etc.) — no
  crashes, numeric clamping holds in every case.

### Fixed
- **`install.sh --global` crashed with an unhandled `FileNotFoundError`
  on a fresh machine** where `~/.config/opencode/` doesn't exist yet —
  a plausible, likely common first-run scenario, not an edge case.
  Found by a 9th adversarial review round that actually ran the
  installer in a sandboxed temp `HOME`, not just read the shell
  script. `set -euo pipefail` aborted the whole install right after
  the node-deps step, printing a raw Python traceback instead of
  "Done." The config-writing step never created the parent directory
  before `open(config_path, "w")`. Fixed with `os.makedirs(...,
  exist_ok=True)` before the write; live-verified against the exact
  failing scenario (confirmed the pre-fix script really does raise
  there, and the fix resolves it, writing a correct config).

### Verified clean (round 9, live-execution)
- `postApiReply`'s JSON payload under adversarial content: no shell
  injection (confirmed empirically, not assumed, against `spawn()`'s
  array-args form), NUL bytes and lone UTF-16 surrogates both escape
  safely before reaching argv (different, safer mechanism than round
  7's direct-encode bug — checked and found not to reproduce here),
  oversized payloads reject cleanly via the existing `'error'` handler
  (no crash) and, when reachable through a real oversized form option
  value, are already caught by `handleFormAsked`'s existing
  `form-reply-failed`/`alertHuman` path.
- `formSeen`'s size-cap clearing (added round 8) reopening the
  in-memory "already being processed" gate for a still-in-flight form:
  confirmed this does happen, but `claimReply`'s file-based lock
  (`.jev-gate-replied/form:<id>`) catches every re-discovery — stress
  test with ~2200 concurrent forms and repeated cap-clears produced
  exactly one gate evaluation and exactly one reply per form, zero
  duplicates. The durable backstop holds under real, not just
  reasoned-about, concurrency.
- `install.sh --project` / `uninstall.sh` against no config, an
  unrelated-schema config, a config with an existing gate entry
  (re-running doesn't duplicate it), and invalid-JSON configs (crashes
  with an unfriendly error, but the original file is left byte-for-byte
  untouched — no data loss either way).

### Fixed
- **`claimReply`: the marker directory existing as a plain file
  permanently misclassified every claim as "lost" instead of
  "error".** Found and live-verified by an 8th adversarial review
  round. `fs.mkdirSync`'s `EEXIST` (the marker *directory path* itself
  is unusable) and `fs.writeFileSync`'s `EEXIST` (this specific
  requestID's marker already exists — the intended case) shared one
  catch block, both mapped to `"lost"`. A broken marker path meant
  every permission and form, forever, got logged as the misleading
  `duplicate-suppressed` (implying a race with a live second
  instance, not a broken path) with no self-healing — contradicting
  `claimReply`'s own documented contract ("error — marker unusable,
  evaluate anyway"). Split into two try/catch blocks so a broken
  marker *directory* correctly reports `"error"`.
- `claimReply`: an all-alnum `requestID` over Linux's 255-byte
  `NAME_MAX` hit `ENAMETOOLONG` on the raw-filename fast path,
  silently reopening the double-evaluation race this function exists
  to close (confirmed live: two racing claims for an identical
  5000-char ID both returned `"error"`, not won/lost). The fast path
  now also bounds length, falling through to the hashed (fixed
  64-char) filename above 200 chars.
- **`scripts/measure.py` crashed entirely — no report at all — on a
  JSON-valid-but-wrong-shape log line**, despite its own docstring
  claiming to tolerate corrupt lines: a non-object top-level value, a
  non-numeric `elapsedMs` string, or a non-numeric `usage.input_tokens`
  string all threw uncaught. New `_safe_float`/`_safe_int` helpers and
  a shape check in `load()` (same "corrupt" bucket as unparseable
  JSON) close this for the whole class instead of one field at a time.
- A `NaN`/`Infinity` `elapsedMs` silently skewed `measure.py`'s
  p95/mean for the entire report with no warning, and made `--json`
  output invalid JSON (`json.dumps`'s default `allow_nan=True` emits
  bare `NaN`/`Infinity` tokens). Same bug class round 6 fixed for
  `decision.confidence` in `client.py`, unreviewed in `measure.py`
  until now — `_safe_float` rejects non-finite the same way
  `_finite_float` does.
- `measure.py --by-session`'s plain-text output crashed on a lone
  UTF-16 surrogate in `sessionID` (same root-cause class as round 7's
  `sha256_hex` fix, in a different, unfixed location) — sanitized with
  `errors="replace"` before printing.
  32 TS tests now (was 30), 57 Python tests (was 52, including a new
  `tests/test_measure.py` — this script had zero test coverage before).

### Fixed
- **A lone UTF-16 surrogate in `HALT.detail` silently dropped the entire
  log line for that event, with no error anywhere.** Found by a 7th
  live-execution review round (following round 6's method: run real
  code against adversarial input, don't just read it). `sha256_hex`
  (`schemas.py`) used the default strict `"utf-8"` codec, which raises
  `UnicodeEncodeError` on a lone surrogate. Reachable in *ordinary*
  use, no attacker needed: `index.ts` truncates untrusted text with
  plain `.slice(0, N)` at several fixed boundaries (`joined.slice(0,
  4000)`, per-turn `.slice(0, 1000)` in `objectiveFor`, etc.), and JS
  `.slice()` cuts UTF-16 code units, not code points — any emoji or
  other non-BMP character landing exactly on one of those cuts leaves
  a lone surrogate. Two consequences from the one root cause,
  live-verified end to end: `build_state()` (called before Jev is
  invoked) raised, so the gate never even asked Jev and fell open to a
  generic `ask-human`/`"exception"` — safe, but wrong reason and a
  real decision Jev could have made correctly; separately,
  `_write_log_entry()`'s blanket `except: pass` swallowed the same
  exception, so **that log line was never written at all** — a
  0-byte-file-shaped silent gap in the audit trail, not a malformed
  line someone would notice. Fixed with `errors="replace"` instead of
  the strict codec — this function only ever hashes text for logging/
  dedup, not for anything requiring exact byte fidelity. Verified the
  new regression tests actually catch this (reverted the fix, watched
  both fail with the real `ask-human`/`UnicodeEncodeError`-adjacent
  symptoms, restored it).
  52 Python tests now (was 50).

### Verified clean (round 7, live-execution)
- Every `spawn()` call site in `index.ts` (re-counted from scratch:
  exactly 5, matching round 6) — all have a working `.on("error",
  ...)` listener; live-ran the three not covered by round 6's fix
  (`listPendingForms`, `postApiReply`, `spawnGate`) against an empty
  `PATH`, no crashes.
- The logging path otherwise: very long strings, embedded
  `\n`/`\r\n`/`\t`, unicode not at a truncation boundary, and deep
  (500-level) nesting all round-trip through `_write_log_entry`/
  `logLine` and pass strict JSON parsing.

### Fixed
- **CRITICAL: `alertHuman()` crashed the entire opencode host process on
  any machine without `notify-send`/`zenity` installed.** Found by a
  6th adversarial review round that drove the real `setup(ctx)` event
  loop end to end (not just read the code) against a fake `ctx`.
  `child_process.spawn()` reports a missing binary asynchronously via
  an `'error'` event, not the synchronous throw the existing
  `try/catch` around each `spawn()` call catches. Both `spawn()` calls
  in `alertHuman` — the escalation path for nearly every fail-open/
  ask-human outcome in the plugin — had no `.on("error", ...)`
  listener, unlike every other `spawn()` call in the file. An
  unhandled `'error'` event is fatal to the whole Node process: the
  *first* time any permission needed a human alert on a headless
  machine (the norm for CI/servers/containers — exactly this
  project's own stated target for autonomous/headless use), the
  entire host died, taking down permission gating for every session,
  not just the one that triggered it — worse than a silent hang, a
  full outage from a completely ordinary condition, no attacker
  interaction required. Live-verified: reproduced the crash against
  the real exported function with `PATH` pointed at a directory with
  neither binary, confirmed the fix survives the same repro, confirmed
  reverting the fix makes the new regression test fail (child process
  exits 1) before restoring it. Fixed by adding the same
  `.on("error", ...)` listener already used elsewhere in the file.
- A non-finite `decision.confidence` (`NaN`/`Infinity`) from Jev's
  response passed straight through `client.evaluate()`'s `float()`
  calls uncaught — `float()` doesn't reject non-finite values,  and
  `json.dumps` then emits an invalid bare `NaN` token that breaks the
  TS side's `JSON.parse` of the gate's stdout, converting a field
  `decision.combine()` doesn't even use for branching ("no
  thresholds") into a downstream parse failure instead of a clean
  `bad-response`/ask-human. New `_finite_float()` helper (`client.py`)
  rejects non-finite values explicitly, caught by the existing
  `bad-response` error-wrapping path.
  30 TS tests now (was 29), 50 Python tests (was 49).

### Verified clean (round 6, live-execution)
- A `session.deleted` event racing an in-flight, un-awaited form
  evaluation for the same session — no crash, no double-reply.
- 7 constructed malformed/unusual `permission.asked` payload shapes
  (missing fields, `data`/`properties` precedence, non-string
  `resources`) — all handled gracefully.
- The poll-based form-discovery path racing the event-subscription
  path for the identical form ID — `claimReply`'s file lock correctly
  allows exactly one evaluation.

### Fixed
- **Session-ended detection was over-broad enough to silently stop
  replying on a still-alive session — the one fail path in the plugin
  with no `alertHuman`.** Found by a 5th, final adversarial review
  round (checking the whole plugin fresh, not just prior rounds'
  fixes). `sessionIsEnded`/`objectiveFor` classified *any* error whose
  message matched `/not\s*found|unknown session|.../i` as "this
  session ended" — but the opencode SDK has a dozen unrelated
  `*NotFoundError` types (`ProviderNotFoundError`,
  `AgentNotFoundError`, `SkillNotFoundError`, `McpServerNotFoundError`,
  `CommandNotFoundError`, `FileNotFoundError`, ...) whose messages
  match the same bare regex — confirmed reachable: "Provider anthropic
  not found" matched. A misclassification here permanently cached the
  session as ended (no TTL) with no Jev call, no reply, and — unlike
  every other error path in the file — no desktop alert either: the
  tool call just silently hangs for the rest of the process's
  lifetime. New `looksLikeSessionGone()` checks the SDK's own `_tag`
  discriminant (`SessionNotFoundError`) first, precise when present,
  and narrows the regex fallback to require "session" co-occurring
  with the not-found-ish wording instead of either alone — closes the
  cross-contamination with sibling `*NotFoundError` types while still
  catching genuine session-ended phrasing.
- The size-cap from an earlier round (`capped()`, meant to bound
  `resolved`/`endedSessions`/`formSeen`) only actually covered
  `endedSessions` on 1 of its 4 write sites — the 3 inside
  `sessionIsEnded`/`objectiveFor`, its most frequently hit path, used
  a bare `.add()` that bypassed the cap. Now all 4 go through
  `capped()`.
- `labelsFromFormField` crashed (uncaught `TypeError`) on a
  `null`/`undefined` entry in a question field's `options` array — a
  legal JSON shape, and one `valueForPick` already guarded against.
  The crash was contained (caught by `handleFormAsked`'s outer
  try/catch, fails open to `ask-human`) but took the whole form's
  auto-answer down over one bad field entry. Now skips the bad entry
  like every other malformed one.
  29 TS tests now (was 25).

### Fixed
- **`valueForPick` ambiguity: two different multichoice options that
  collide after redaction/truncation now route to ask-human instead
  of silently picking the first one.** Found by a third adversarial
  review — this one specifically checking the earlier fixes in this
  session for regressions they might have introduced. Two independent,
  reproducible collisions confirmed: two option labels containing
  different secrets that both redact to `"...[REDACTED]"`, and two
  labels differing only past the 200-char truncation point. Before
  this fix, `valueForPick` returned the first option whose normalized
  label matched, silently applying a different (but still pre-offered,
  still valid) choice than the one Jev actually meant — no error, no
  log signal. Now returns `null` on ambiguity, treated the same as
  "pick not offered": `alertHuman` fires, the form is not answered
  automatically. 25 TS tests now (was 23).

### Documented
- **A known, pre-existing false-positive trade-off in the catastrophic
  kill-list, made explicit.** The same review found that
  `echo "talk about rm -rf / here"` (and similarly `"rm -r\f / in
  docs"`) normalizes to text matching the catastrophic pattern and
  gets instantly rejected — descriptive prose, not a real command.
  Traced this to the existing quote-stripping step (present before
  this session), which this session's backslash-stripping fix (closing
  the `r\m` bypass) widened slightly. Confirmed there's no narrower fix
  available: restricting backslash-stripping to avoid this reopens the
  exact obfuscation bypass it exists to close, since `r\m` has the same
  shape (backslash between two letters) as the false-positive case. It
  fails closed (blocks work, never silently allows), so this is a
  documented usability cost, not a security hole — see the comment
  above the `CATASTROPHIC` array in `index.ts`.

### Fixed
- **Two findings from a confirming second adversarial review** (round
  2, scoped to the multichoice/form flow and the event-loop dedup
  logic — neither had a dedicated review before; round 1's kill-list/
  redaction/injection fixes were out of scope and re-verified clean):
  - Question-tool option labels (`labelsFromFormField`) reached Jev's
    multichoice criteria with no length cap and no redaction, unlike
    `OBJECTIVE`/`HALT.detail`. Not a bypass (the picked option must
    still be one Jev was actually offered, checked independently on
    both sides), but an unbounded, unfenced injection/cost surface.
    Each label is now capped at 200 chars and redacted
    (`normalizedLabel`); `valueForPick` re-derives the same
    normalization at lookup time instead of assuming a positional
    mapping between raw and shown labels, so a truncated/redacted pick
    still round-trips correctly to its real underlying value.
  - `resolved`/`endedSessions`/`formSeen` (the in-memory dedup maps in
    the plugin's main event loop) are never evicted — confirmed by
    review that no success path ever calls `.delete()`/removal on
    them, so a long-lived process accumulates one entry per ever-seen
    requestID/sessionID/formID for its whole uptime. Fixed with a
    size-cap circuit breaker (`capped()`, 2000 entries) rather than
    retrofitting per-entry timestamps through every function signature
    that touches these maps — lower risk for the same practical
    protection.
  A third finding — the event-subscription loop is fully sequential,
  so concurrent permissions queue behind each other under load — is
  **not** fixed here; parallelizing it touches the exact dedup/claim
  logic that caused issue #15/R52/R55/R57's duplicate-evaluation bugs,
  so it's documented as a named, accepted limitation in
  `docs/ARCHITECTURE.md` pending a dedicated, separately-reviewed
  change rather than folded into this cycle.
  23 TS tests now (was 19).

### Security
- CI workflow actions pinned to a full commit SHA (with a version
  comment) instead of a mutable tag (`@v4`/`@v5`) — standard
  supply-chain hardening (a compromised or re-pointed tag can't
  silently change what CI runs). Also checked while at it: the two
  transitive `npm` packages with install scripts flagged locally
  (`msgpackr-extract`'s `node-gyp-build-optional-packages`,
  `protobufjs`'s postinstall) are both well-known native-module/
  version-check patterns from deeply transitive, non-project-controlled
  dependencies (via `@opencode/plugin`) — read both scripts, nothing
  suspicious, no action needed.

### Security
- **Prompt-injection fencing for the brief, and the residual risk
  documented explicitly for the first time.** The same security review
  that found the kill-list/redaction gaps also flagged that
  `OBJECTIVE`/`HALT.detail` (both attacker-reachable: conversation
  text, command/file content) were concatenated into Jev's brief with
  no delimiter between trusted framework text and untrusted content —
  and that this was nowhere documented as an accepted trade-off, only
  silently assumed safe. `build_objective_block` (`schemas.py`) now
  wraps both fields in a per-request random-token fence with an
  explicit "this is data, not instructions" note; any occurrence of
  the fence token inside the untrusted content itself (guessed or
  coincidental) is neutralized first, so it can't forge an early
  closing marker to inject fake trailing `POLICY:`/`QUESTION:` lines.
  This is a partial mitigation, not a fix — documented as such in
  `SECURITY.md` ("Accepted risk: prompt injection into Jev's brief")
  and `docs/ARCHITECTURE.md`, and linked from the README's Safety
  model section. Jev's own judgment over the fenced content remains
  the only real defense; there's no secondary check on `decision.
  combine()`'s output (by design — see "no thresholds").

### Fixed
- **Secret redaction gaps** (both `schemas.py` and `index.ts`, same
  security review as the kill-list fix above): compound identifiers
  like `AWS_SECRET_ACCESS_KEY=...` slipped through because the
  keyword-match pattern required `password`/`secret`/`token`/etc. to
  sit immediately before `=`/`:`, not just appear anywhere in a longer
  identifier — widened so the keyword can be embedded, verified
  against the same 6 existing cases (`password:`, `TYPESAFE_API_KEY=`,
  ...) to confirm no regression. Also added: AWS *temporary* credentials
  (`ASIA` prefix, alongside the existing `AKIA`), raw JWTs with no
  `Bearer` prefix, and credentials embedded in connection-string URLs
  (`scheme://user:PASSWORD@host` — redacts only the password, keeps
  host/port/path visible for debugging). Found live: while building
  the fix, my own first version of the widened keyword pattern
  regressed the existing `password: ...`/`secret=...` cases (a
  `\b[a-z]` mandatory-leading-character bug) — caught by running the
  full existing test suite before shipping, not after.
  **Scope, stated precisely:** this closes exposure to Jev's external
  API (the brief sent over the network); it does not change what's
  logged locally, since `decisions-plugin.jsonl` only ever stores
  `detail_sha256`, never the raw or redacted detail text.
- **Catastrophic kill-list: three real bypasses found and fixed by an
  adversarial security review (opencode subagent attempt got stuck
  in a re-orientation loop without producing a report — a model
  limitation on this specific "reason without new tool calls" task,
  not a gate issue; escalated to a Claude Sonnet subagent, which
  delivered a verified, well-evidenced report; every finding
  independently re-reproduced before fixing).** `normalizeCommand`
  (`index.ts`) only handled the braced `${IFS}` form and never
  stripped backslashes, so `rm$IFS-rf$IFS/` (bare `$IFS`, standard
  bash word-splitting) and `r\m -rf /` (backslash-before-ordinary-char
  removal, standard bash) both reached Jev as ordinary text instead of
  being rejected locally — fixed by also handling bare `$IFS` and
  stripping backslashes. Separately, the `CATASTROPHIC` target list
  covered bare `$HOME`/`~`/`/home` but not the *resolved* home path
  (`rm -rf /home/idiaval`) or `/root`, and covered bare `.` but not
  bare `..` (`rm -rf ..`, deletes the parent directory) — fixed by
  adding `/home/<exact-one-segment>`, `/root`, and bare `..`/`../` to
  the target alternation, written narrowly enough that ordinary
  subpath deletes (`rm -rf /home/idiaval/proyectos/viejo`,
  `rm -rf ../build`) still correctly pass through, unchanged from the
  R65/#16 false-positive fix.
  Command substitution (`` $(...) ``/backticks) is a fourth,
  *unfixable-by-regex* bypass — resolving it would require actually
  evaluating the substituted command, which the kill-list correctly
  never does. Rather than a false sense of coverage, it's now
  surfaced to Jev as an explicit risk hint
  (`contains command substitution ... — real effect cannot be
  statically determined`) so the LLM judgment step at least knows to
  be suspicious of it, instead of silently missing it entirely.

### Added
- SAST: `bandit` runs in CI on `src`/`scripts` at `--severity-level
  medium` (a new `sast` job). The threshold is intentional, not a
  bypass: at the default `low` level bandit flags this codebase's
  already-reasoned patterns (the fail-open `try/except/pass`, the
  fixed-argument-list `subprocess.run` calls in `doctor.py` with no
  `shell=True`, and a self-test `assert`), the same call already made
  for ruff's own bandit-style rules (see `pyproject.toml`). A real
  medium/high finding still fails CI.

### Added
- Tests for two CRITICAL gaps found by an opencode subagent test-coverage
  audit (`.dev/test-coverage-audit.md`, gitignored dev artifact; the
  audit also filed HIGH/MEDIUM/LOW findings not yet acted on):
  `client.py`'s `evaluate()` now has tests proving a malformed Jev
  payload (missing answer keys, non-numeric confidence) raises
  `JevCallError("bad-response: ...")` instead of leaking a raw
  `KeyError`/`ValueError`, plus a test for the empty-`api_key` guard.
  `claimReply` (`index.ts`, the exclusive-marker dedup issue #15's fix
  depends on) is now exported and has tests for its `won`/`lost`/`error`
  branches, including that a path-unsafe `requestID` gets hashed rather
  than used as a raw filename.
- All remaining HIGH/MEDIUM/LOW findings from that same audit now have
  tests too (46 Python tests, up from 29; 14 TS tests, up from 7):
  `client.py`'s `_real_transport` object-style SDK answers and
  malformed-`usage` swallow; `cli.py`'s `_classify_error` (all four
  branches), malformed-event fail-open, `bad-response` classification
  from a `JevCallError`, non-dict `pick` handling, `pick` ignored on
  `deny`, `_error_box["error_class"]` on a bad pick, `main()`'s
  empty/invalid-stdin default and `JEV_GATE_CLI_LOG=0` skip,
  `_write_log_entry`'s `error_class` emission on fail-open;
  `decision.py`'s `None`/empty/case-variant inputs; `schemas.py`'s
  `redact_secrets` non-string/empty passthrough and additional token
  patterns (Basic/AKIA/`github_pat_`/`xox*`/`sk-`), and
  `build_objective_block`'s empty-objective fallback, truncation caps,
  and missing-`kind`/`tool` defaults. On the TS side: `normalizeCommand`
  actually defeating quote/`${IFS}`/separator/`/bin/rm` obfuscation
  (not just claimed in a comment), the remaining `CATASTROPHIC` list
  entries, `kindFor`'s untested action/hint mappings, `redactSecrets`'
  non-bearer token patterns, and `postApiReply` (now exported) rejecting
  correctly on a non-zero exit and on a missing `opencode` binary.
  Deliberately left uncovered: `postApiReply`'s 10s timeout branch (a
  real-time test would slow the suite for one already-well-understood
  path) and the in-flight/resolved request dedup in the plugin's main
  event loop (embedded in the live subscription closure, not a pure
  function — extracting it for testability would mean touching the
  exact code that caused issue #15/R52/R55/R57's duplicate-eval bugs,
  a job for its own reviewed change, not a test-coverage sweep).

### Security
- Dependency audit: `pip-audit` against declared Python deps — clean,
  no known vulnerabilities. `npm audit` (plugin) — 11 moderate
  advisories, all the same root cause
  ([GHSA-8988-4f7v-96qf](https://github.com/advisories/GHSA-8988-4f7v-96qf),
  unbounded memory allocation in `@opentelemetry/core`'s W3C Baggage
  propagation), pulled in transitively through `@opencode/plugin`
  (our only runtime dependency, deliberately pinned to `2.0.11`). This
  plugin never calls the OpenTelemetry API itself and doesn't process
  external Baggage headers, so the advisory's trigger path isn't
  reachable from our code; it's opencode's own telemetry surface, not
  ours. `npm audit fix` can't resolve it without forcing a bump that
  would break the `@opencode/plugin` pin — blocked on upstream
  updating its own `@opentelemetry/*` deps, not actionable from here.

### Removed
- Dead code found by an opencode subagent audit
  (`.dev/dead-code-audit.md`, not published — see `AGENTS.md`),
  verified independently before removal: `parseOptions()` in
  `index.ts` (zero callers, superseded by `labelsFromFormField`), the
  unreachable `kind === null` branch in `handleOne` (`kindFor` never
  actually returns `null` despite its old type signature), the
  `WRITE_ACTIONS` no-op membership check (both branches returned
  `"write"`), a dead `meta` extraction in the form-poll loop, and
  Python's `ALLOWED_MODELS` no-op guard (`if ...: pass`) in
  `client.py`. Also collapsed `replyFormAnswer` and `replyPermission`
  (`index.ts`) onto one shared `postApiReply` helper — they duplicated
  ~25 lines of spawn/timeout/stderr handling, which is exactly the
  reply logic issue #15 needed fixed in two places at once.

### Fixed
- Catastrophic-pattern regex no longer flags ordinary subpath deletes
  as whole-filesystem wipes: `rm -rf ./build`, `rm -rf ~/some/subdir`,
  `rm -rf $HOME/some/subdir` and similar were being hard-rejected
  without ever reaching Jev, because the pattern matched any command
  starting with `.`, `~/`, or `$HOME`/`${HOME}` regardless of what
  followed. Now only the actual dangerous forms (bare `/`, `~`, `.`,
  `$HOME`, `${HOME}`, `/home`, and their trailing-slash variants) are
  caught. Added `plugin/jev-decision-gate/index.test.ts` (Node's
  built-in `node:test`, run via `npm --prefix plugin test`) covering
  `isCatastrophic`, `redactSecrets`, and `kindFor` — previously the
  only TS-side check was `tsc --noEmit`.
- **Issue #15, fixed.** Ordinary `read`/`write`/`bash` permission
  replies intermittently failed with `reply-failed: Permission request
  not found`, leaving the tool call hanging. First diagnosed (wrongly)
  as a race against a short server-side window, and a latency
  mitigation shipped on that theory; falsified hours later when a
  permission a reply had just failed on was found still pending
  server-side *minutes* later, and a raw `opencode api POST
  .../permission/{id}/reply` on it succeeded immediately. Root cause:
  `ctx.permission.reply()` (the `@opencode/plugin` SDK method) is
  itself unreliable in this environment — never a timing issue. Fixed
  by no longer calling it: `replyPermission` in `index.ts` now shells
  out to `opencode api POST .../permission/{id}/reply` at all four
  call sites that used it, the same pattern `replyFormAnswer` already
  used reliably for form answers. Re-verified live: 17/17 successes
  under concurrent load that reliably reproduced the original failures
  (elapsedMs up to 1032ms, well past the previously-suspected ~832ms
  "deadline" — there never was one). See `docs/TROUBLESHOOTING.md` for
  the full story, including the abandoned first theory, kept so the
  dead end isn't rediscovered.
- Golden eval expanded from 6 to 13 cases (`tests/golden.json`), and
  `tests/test_golden.py` now checks every case against an explicit
  `expected_action`, not just the `must_not_allow` traps — half the
  cases previously loaded but were never asserted against anything.
  New cases cover an unknown `decision.choice` degrading to
  ask-human, a multichoice pick outside `options`, multichoice with no
  `options` at all (protects the R54 fix), confidence having zero
  effect on the outcome in both directions (protects the "no
  thresholds" design), a positive `write` case, and a `doom_loop`
  destructive case.

### Added
- README badges (CI, license, Python, Node), a top-of-file risk
  disclaimer for the auto-approval model, and a contents line.
- `permissions: read-all` on the `ci` workflow — no job writes to the
  GitHub API.
- Repo description and topics updated on GitHub for visibility.

### Known limitations
- The question/form auto-answer path is live-verified for the
  `ELEGIDO=pizza` repro but not proven to close every hang case; see
  `docs/TROUBLESHOOTING.md` "Question dialog hangs".
- **`opencode run --auto` bypasses the gate entirely, including the
  catastrophic kill-list** — confirmed with a zero-risk live repro
  (`terraform destroy`, `terraform` not installed): executed under
  `--auto`, correctly blocked (`executed: false`) via the raw session
  API. `--auto` resolves permissions client-side without waiting for
  `permission.asked` subscribers, so no plugin can win that race; not
  fixable from inside this plugin. See `docs/TROUBLESHOOTING.md` and
  issue #21. Use the raw session API for headless work instead.

## [0.2.0] - 2026-09-21

### Added
- **Full autonomy over documented OpenCode permission keys.** Jev
  evaluates allow/deny/ask-human for every key in OpenCode's
  permissions docs (`read`, `edit`/`write`/`apply_patch`, `glob`,
  `grep`, `bash`, `task`, `skill`, `lsp`, `webfetch`, `websearch`,
  `external_directory`, `doom_loop`); unknown actions fail-open to
  ask-human.
- **Question tool: two-phase handling via the form API.** The
  `question` permission is passthrough-allowed instantly (no Jev
  call); the question tool then opens a form
  (`metadata.kind=question`), which the plugin polls for
  (`GET /api/form`) and answers on Jev's behalf via
  `POST /api/session/{sessionID}/form/{formID}/reply`. Live-verified
  on 2.0.11 (`ELEGIDO=pizza`, idle succeeded) — see
  `docs/TROUBLESHOOTING.md` for what that does and doesn't prove.
- `scripts/verify_autonomy.py`: non-interactive check that the plugin
  owns permission + form answers against a running opencode service.
- Human alert on ask-human/fail-open: `notify-send -u critical` plus a
  best-effort `zenity --warning` popup.
- Unified v2 decision log (`sessionID`, `requestID`, `kind`,
  `detail_sha256`, `elapsedMs`, `inst`/`pid` for cross-instance
  diagnosis).
- Curated Jev brief with bounded multi-turn conversation context
  (`objectiveChars` / `JEV_GATE_OBJECTIVE_CHARS`) and secret redaction
  before both the Jev call and the log, on both the TS and Python
  sides.
- Hardened catastrophic-pattern kill list (command normalization
  defeats trivial obfuscation) rejected locally, without calling Jev.
- Configurable gate timeout (`timeoutMs` / `JEV_GATE_TIMEOUT_MS`, max
  30s) with output caps and SIGTERM→SIGKILL escalation.
- Python spawn auto-detects a mise-managed interpreter
  (`options.pythonBin` / `JEV_GATE_PYTHON`) and sets `PYTHONPATH` so
  `typesafe_sdk` resolves even when the opencode service's own
  `python3` lacks it.
- `scripts/install.sh`, `scripts/uninstall.sh`, `jev-gate-doctor`
  (`python3 -m jev_gate.doctor`), `.env.example`.
- Public-repo standards: LICENSE, CONTRIBUTING, Code of Conduct,
  SECURITY, issue/PR templates, CI (pytest × 3.10-3.12, ruff, tsc), and
  pre-commit hooks.
- `scripts/measure.py`: rates, fail-open breakdown, p95, cost,
  `--by-session`.
- `AGENTS.md`.

### Changed
- Jev's `decision` answer wins at any confidence — no thresholds.
  Safe/risk answers are recorded as evidence, not vetoes.
- One evaluation per requestID, claimed via an exclusive marker file
  (`.jev-gate-replied/<requestID>`) before calling Jev, not just
  before replying — `setup()` runs more than once per opencode
  process (confirmed: same `pid`, different `inst`), so without this
  every permission was evaluated 2-3x and raced to reply. Losers skip
  entirely; late duplicates log `duplicate-suppressed`.
- Single-writer log: the plugin logs every decision; the Python CLI
  stays silent when spawned by the plugin.
- Pin `@opencode/plugin` to `2.0.11` (was `latest`).
- Prefer `TYPESAFE_API_KEY` env over cleartext `typesafeKey` in
  config.
- Session-end detection tracks `session.deleted` and checks
  `session.get` for `time.archived` instead of silently skipping.

### Fixed
- Separate `WRITE_ALLOW` / `MULTICHOICE_ALLOW` thresholds (were
  aliased to the read threshold); multichoice criteria carry
  per-option summaries instead of `None`.
- Multichoice without parseable options no longer 400s Jev — the
  `pick` question is only asked when options exist.
- `doctor.py` checks both `opencode-v2` and `opencode` binary names,
  since the v2 line is sometimes installed under a different command
  while beta.

### Environment / upstream findings (this project's dev machine + upstream opencode)
- Confirmed `@opencode-ai/plugin`'s `permission.ask` hook has been
  dead code since v1.3.0 — this gate targets `@opencode/plugin`
  instead. Confirmed `"permission": "allow"` makes opencode 2.0.11
  skip `permission.asked` entirely, so the gate requires
  `"permission": "ask"`. Full detail, issue links, and the full
  timeline of question-dialog-hang fix attempts (including the ones
  that didn't work) live in `docs/TROUBLESHOOTING.md`.

## [0.1.0] - 2026-09-19

- v2 plugin with session-aware objective, on/off switch.
- Threshold policy with golden traps, stdin/stdout gate with fail-open.
