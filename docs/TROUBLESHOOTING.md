# Troubleshooting

## "It never asks Jev, I always get the manual prompt"

That IS the fail-open design — but find out why:

```bash
python3 -m jev_gate.doctor
tail -5 "${JEV_GATE_LOG:-decisions-plugin.jsonl}"
python3 scripts/measure.py
```

| Symptom in log | Cause | Fix |
| -------------- | ----- | --- |
| `reason: fail-open, error_class: missing-key` | no API key | `export TYPESAFE_API_KEY=...` |
| `error_class: transport` / `missing-sdk` | `typesafe-sdk` not installed | `pip install -e .` from repo root |
| `error_class: gate timeout` | Jev slow / offline | raise `timeoutMs` (max 30000) |
| no log lines at all | hook never fired | need opencode **v2** + a `permissions: [... effect: ask]` entry |
| `reason: catastrophic-pattern` | command matched kill-list | intended: rewrite the command |

## opencode 1.x vs v2

Stable 1.x never fires `permission.asked`, so the gate sleeps without
disturbing you. Run `opencode --version`: it must start with `2`.
The 12 old plugins failing under v2 is expected — they are v1-only.

Global `~/.config/opencode/opencode.json` may keep both keys on purpose:

- `plugin` — v1 plugins for stable 1.x
- `plugins` — v2 plugins (this gate). Put the API key in
  `TYPESAFE_API_KEY` (e.g. `~/.config/opencode/secrets.env`), not in JSON.

## Which log file?

Canonical: the path in `logFile` / `JEV_GATE_LOG`, default
`<repo>/decisions-plugin.jsonl`. `measure.py` reads `JEV_GATE_LOG`
first, then both `decisions*.jsonl` fallbacks.

## Key hygiene

Prefer env (`TYPESAFE_API_KEY`) over `typesafeKey` in JSON (which sits
in cleartext on disk). The key is never logged; `doctor` only prints
whether it is set.

## Still stuck?

Open a bug issue with the template: version, env, redacted log lines,
repro steps. Expectation is always fail-open to ask-human.
