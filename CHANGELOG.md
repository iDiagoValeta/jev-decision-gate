# Changelog

All notable changes to this project are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
versioning follows [SemVer](https://semver.org/).

## [Unreleased]

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
