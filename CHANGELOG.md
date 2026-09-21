# Changelog

All notable changes to this project are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
versioning follows [SemVer](https://semver.org/).

## [Unreleased]

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
