# jev-decision-gate plugin (OpenCode v2)

Lets Jev answer permission prompts automatically. Allow goes through,
deny blocks, anything uncertain falls back to your manual prompt.
Agent questions to you are triaged too: Jev lets good ones through
and rejects noise, but the answer is always yours — the v2 permission
reply carries no option choice, so auto-answering is not possible.

Requires OpenCode v2 (stable 1.x never fires the permission hook),
Python 3.10+ with the `typesafe-sdk` package, and a TypeSafe API key.

Install in a project:

```jsonc
// opencode.jsonc
{
  "permissions": [{ "action": "shell", "resource": "*", "effect": "ask" }],
  "plugins": [
    {
      "package": "/absolute/path/to/jev-decision-gate/plugin/jev-decision-gate",
      "options": {
        "typesafeKey": "<TYPESAFE_API_KEY>",
        "logFile": "/absolute/path/to/decisions-plugin.jsonl",
      },
    },
  ],
}
```

For every session, install once globally instead: put the same
`plugins` entry in your global config and every project inherits it.

Options (all optional):

| Option        | Env fallback      | Default                                    |
| ------------- | ----------------- | ------------------------------------------ |
| `typesafeKey` | `TYPESAFE_API_KEY`| "" (gate fail-opens to ask-human)          |
| `logFile`     | `JEV_GATE_LOG`    | `<repo>/decisions-plugin.jsonl`            |
| `gateDir`     | `JEV_GATE_DIR`    | repo root (where `src/jev_gate` lives)     |
| `enabled`     | `JEV_GATE_ENABLED`| `true` (`false`, `0`, `off`, `no` disable) |

To disable without uninstalling, set `"enabled": false` or export
`JEV_GATE_ENABLED=0`. While disabled the plugin subscribes to nothing
and every permission falls back to the manual prompt.

The plugin shells out to the Python gate (`python3 -m jev_gate.cli`).
Each decision is appended to the log file as one JSON line
(`tool`, `gateAction`, `reason`, `confidence`, `model`, `elapsedMs`,
`objectiveChars`) without secrets. The API key is never logged.
