# Changelog

All notable changes to this project are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
versioning follows [SemVer](https://semver.org/).

## [Unreleased]

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
