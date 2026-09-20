# jev-decision-gate plugin (OpenCode v2)

Lets Jev answer permission prompts automatically. Allow goes through,
deny blocks, anything uncertain falls back to your manual prompt.
Agent questions to you are triaged too: Jev logs a numbered
recommendation (`pick`), but the answer is always yours — the v2
permission reply carries no option choice, so auto-answering is not
possible.

Requires OpenCode on the `@opencode/plugin` line (`permission.asked`
events — the more common `@opencode-ai/plugin` line does not fire it,
see the repo's `docs/TROUBLESHOOTING.md`), `"permission": "ask"` in
your config, Python 3.10+ with the repo installed (`pip install -e .`
for `typesafe-sdk` + `jev_gate`), and a TypeSafe API key.

Fastest path: `./scripts/install.sh --project|--global` from the repo
root, then `export TYPESAFE_API_KEY=...`.

Install in a project:

```jsonc
// opencode.jsonc
{
  "permission": "ask",
  "plugins": [
    {
      "package": "/absolute/path/to/jev-decision-gate/plugin/jev-decision-gate",
      "options": {
        "typesafeKey": "<TYPESAFE_API_KEY>", // or env TYPESAFE_API_KEY (preferred)
        "logFile": "/absolute/path/to/decisions-plugin.jsonl",
      },
    },
  ],
}
```

For every session, install once globally instead: put the same
`plugins` entry in your global config and every project inherits it.

Options (all optional):

| Option        | Env fallback          | Default                                    |
| ------------- | --------------------- | ------------------------------------------ |
| `typesafeKey` | `TYPESAFE_API_KEY`    | "" (gate fail-opens to ask-human)          |
| `logFile`     | `JEV_GATE_LOG`        | `<repo>/decisions-plugin.jsonl`            |
| `gateDir`     | `JEV_GATE_DIR`        | repo root (where `src/jev_gate` lives)     |
| `enabled`     | `JEV_GATE_ENABLED`    | `true` (`false`, `0`, `off`, `no` disable) |
| `timeoutMs`   | `JEV_GATE_TIMEOUT_MS` | `15000` (clamped to 1000–30000)            |
| `objectiveChars` | `JEV_GATE_OBJECTIVE_CHARS` | `4000` (clamped to 200–20000), how much recent conversation (both roles) Jev sees |

Precedence: `options > env > default`. Prefer env for the key so it
never sits in cleartext JSON.

To disable without uninstalling, set `"enabled": false` or export
`JEV_GATE_ENABLED=0`. While disabled the plugin subscribes to nothing
and every permission falls back to the manual prompt.

The plugin shells out to the Python gate (`python3 -m jev_gate.cli`)
with a minimal env. Each decision is appended (schema v2, mode 0600)
as one JSON line (`at`, `sessionID`, `requestID`, `tool`, `kind`,
`gateAction`, `reason`, `confidence`, `model`, `pick`, `elapsedMs`,
`objectiveChars`, `detail_sha256`, `hasKey`) without secrets.
The API key is never logged. Catastrophic commands are rejected
locally (`reason: catastrophic-pattern`) without calling Jev.
