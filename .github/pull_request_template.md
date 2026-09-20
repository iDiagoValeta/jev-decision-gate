## What

## How to test

```bash
python3 -m pytest -q
```

## Checklist

- [ ] Fail-open to ask-human preserved (no silent allow on error)
- [ ] No secrets in logs or Jev payloads
- [ ] Decision-logic change (`decision.py`, `kindFor`) covered by a golden test
- [ ] CHANGELOG.md updated under `[Unreleased]`

Closes #
