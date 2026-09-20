# Contributing

## Quick start

```bash
git clone git@github.com:iDiagoValeta/jev-decision-gate.git
cd jev-decision-gate
python3 -m pip install -e ".[dev]"
npm --prefix plugin install
python3 -m pytest -q
```

## Branches & commits

- Branch from `main`: `feat/<scope>`, `fix/<scope>`, `docs/<scope>`.
- Conventional Commits: `feat:`, `fix:`, `test:`, `docs:`, `chore:`.
- One logical change per commit. Keep `main` green.

## Safety contract (must not break)

1. Fail-open to `ask-human` on any error — never silent `allow`.
2. No secrets in logs or Jev payloads (run `pytest -q` — redaction tests cover this).
3. Threshold changes require a golden test in `tests/golden.json`.

## Pull requests

- Fill the PR template, link `Closes #<n>`.
- `pytest -q` green, `tsc --noEmit` green for plugin changes.
- Update `CHANGELOG.md` under `[Unreleased]`.
