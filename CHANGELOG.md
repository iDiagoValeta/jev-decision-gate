# Changelog

All notable changes to this project are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
versioning follows [SemVer](https://semver.org/).

## [Unreleased]

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
