# Changelog

All notable changes to this project are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
versioning follows [SemVer](https://semver.org/).

## [Unreleased]

### Changed (2026-09-20, multichoice reply removed — did NOT fix the hang)
- `multichoice` permission replies removed again: the reply to a
  `multichoice` permission consistently arrives after opencode's client
  has already committed to its own confirmation UI, so it always lands
  as `"Permission request not found"` regardless — the manual Allow
  click is unavoidable for this tool either way, so skipping the reply
  costs nothing. This was tried expecting it to also fix the hang after
  picking an option (a prior test seemed to show the reply attempt
  itself was the corrupting factor) — **verified live on 2.0.11 that it
  does not fix it.** Picking still hangs with the plugin enabled, even
  with zero reply attempted. Root cause still unknown; see
  `docs/TROUBLESHOOTING.md` "Question dialog hangs" for the full
  timeline and what's actually been ruled out before trying a fourth
  fix.
- Environment config: found and applied `opencode-pty`'s own native v2
  build (`opencode-pty/v2` — a real `./v2` export, no shim needed).
  Removed the 9 other community plugins and `opencode-worktree` from
  global config — none ship a native v2 entry point, and
  `opencode-worktree`'s own `package.json` points at a file that
  doesn't exist in what got published. A hand-written v1→v2
  compatibility shim was considered for the rest and deliberately not
  built: three are auth plugins, and a shim bug in a credential flow is
  worse than the plugin not loading.

### Changed (2026-09-20, environment consolidation)
- Removed every redundant/stale opencode install accumulated across
  sessions on the dev machine (a hand-copied `opencode-v2` binary, a
  pnpm-global `opencode-ai@1.18.25`, a stale `~/.opencode/bin/opencode`,
  the desktop app) — one `opencode` install now, 2.0.11.
- Confirmed `@opencode-ai/plugin`'s `permission.ask` hook is dead code
  since v1.3.0 (upstream issue/PR links in TROUBLESHOOTING) — this gate
  cannot target that line today; it stays on `@opencode/plugin`.
- Confirmed `"permission": "allow"` makes opencode 2.0.11 skip emitting
  `permission.asked` entirely. Global/project config now uses
  `"permission": "ask"` — required for the gate to do anything.
- Tested the 12 community plugins previously in the global config
  against 2.0.11: 10 fail to load (wrong Hooks shape for this API
  line), 2 work (`superpowers`, `opencode-dcp`). See TROUBLESHOOTING
  for the full list.
- `doctor.py`'s opencode-version check already handled a single-binary
  environment correctly; no code change needed there.

### Fixed (2026-09-20, duplicate Jev calls; question-hang still open)
- Tried making `multichoice` never auto-reply, on the theory that the
  plugin's own reply was racing the human's answer for the same
  requestID. Reverted: it just replaced the hang with a mandatory
  manual Allow/Reject click before every question, which defeats the
  point of the gate. Jev still approves the tool call for multichoice
  like any other kind; `pick` stays log-only, never submitted as the
  human's answer. The dialog-hang report is still open — see
  `docs/TROUBLESHOOTING.md`.
- Cross-instance claim moved before the Jev call, not just before the
  reply: `setup()` runs more than once per opencode process (confirmed
  in production logs: same `pid`, different `inst`), so every
  permission request was being evaluated 2-3x and racing to reply. The
  losing instance now skips entirely — no Jev call, no reply attempt —
  instead of evaluating anyway and discovering the loss only at reply
  time.
- `doctor.py` checks both `opencode-v2` and `opencode` binary names
  (v2 is often installed under a different command than `opencode`
  while beta) instead of assuming `opencode --version` reflects v2.
- `objectiveFor` sends a bounded multi-turn transcript (both user and
  assistant text, default 4000 chars, `options.objectiveChars` /
  `JEV_GATE_OBJECTIVE_CHARS`) instead of just the last 3 user messages
  capped at 500 chars — Jev can now see recent agent actions, not only
  the human's asks, when judging alignment. `schemas.py`'s own cap
  raised from 500 to 8000 so it no longer silently re-truncates the
  plugin's wider budget.
- Added `AGENTS.md`.

### Fixed (2026-09-20, issues #2 #3 + config hygiene)
- Pin `@opencode/plugin` to `2.0.11` (was `latest`).
- Session-end detection: track `session.deleted`, check
  `session.get` for `time.archived`, and log
  `reason: session-ended` (or `missing-ids`) instead of silent skip.
- Prefer `TYPESAFE_API_KEY` env over cleartext `typesafeKey` in
  global OpenCode config.

### Changed (2026-09-20, live-fire fixes)
- Jev decides with no confidence thresholds: the `decision` answer
  wins at any confidence (allow/deny/ask-human). Safe/risk stay as
  evidence. Unknown strings and errors still fail to ask-human;
  catastrophic patterns still bypass Jev.
- One evaluation per requestID: duplicate `permission.asked`
  emissions share the in-flight promise; late ones log
  `duplicate-suppressed` instead of re-calling Jev or double-replying.
- Single-writer log: only the plugin writes when it spawns the gate.
- `measure.py`: blocks = catastrophic-pattern + jev-deny.

### Fixed (2026-09-20, live-fire)
- Multichoice without parseable options no longer 400s Jev
  (`Choice question must have at least one choice`): the `pick`
  question is only sent when options exist; otherwise the
  allow/deny verdict flows with `pick: null`.
- Fail-open now carries `error` (stdout) → `error_class` (plugin
  log), so Jev-side failures stay visible under single-writer.
- One reply per request across plugin instances: first claimant wins
  via an exclusive marker (`.jev-gate-replied/<requestID>`); losers
  log `duplicate-suppressed`. Every line carries `inst`+`pid` plus
  `resKinds`/`optionsCount` for diagnosis.

### Added
- Unified v2 decision log (`sessionID`, `requestID`, `kind`, `detail_sha256`, `elapsedMs`).
- Curated Jev brief + secret redaction before send and log.
- Hardened catastrophic patterns with normalization (pipe-to-shell, force-push, home deletes).
- Configurable gate timeout (`timeoutMs` / `JEV_GATE_TIMEOUT_MS`, max 30s) with stderr caps.
- `scripts/install.sh`, `scripts/uninstall.sh`, `scripts/doctor.py`, `.env.example`.
- Public-repo standards: LICENSE, CONTRIBUTING, CoC, SECURITY, issue/PR templates, CI, pre-commit.
- `scripts/measure.py` v2: rates, fail-open breakdown, p95, cost, `--by-session`.

### Fixed
- Separate `WRITE_ALLOW` / `MULTICHOICE_ALLOW` thresholds (were aliased to read threshold).
- Multichoice criteria carry per-option summaries instead of `None`.

## [0.1.0] - 2026-09-19

- v2 plugin with session-aware objective, on/off switch.
- Threshold policy with golden traps, stdin/stdout gate with fail-open.
