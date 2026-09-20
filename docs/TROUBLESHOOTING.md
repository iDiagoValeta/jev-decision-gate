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
| `reason: fail-open, error_class: missing-key` | no API key | `export TYPESAFE_API_KEY=...` (must be set in the *service's* env — see below) |
| `error_class: transport` / `missing-sdk` | `typesafe-sdk` not installed | `pip install -e .` from repo root |
| `error_class: gate timeout` | Jev slow / offline | raise `timeoutMs` (max 30000) |
| no log lines at all, `permission: "allow"` in config | confirmed: v2.0.11 does not emit `permission.asked` at all when the ambient mode is already `allow` — nothing to intercept | set `"permission": "ask"` (global or project config); that's what lets the gate substitute Jev for the human in the first place |
| no log lines at all, `permission: "ask"` already set | hook never fired for another reason | check `opencode debug config` resolves your plugin path; re-check with `python3 -m jev_gate.doctor` |
| `reason: catastrophic-pattern` | command matched kill-list | intended: rewrite the command |

## Which opencode, which version

This project only works on the `@opencode/plugin` API line (the one
with `permission.asked` events) — installed as plain `opencode`,
currently tracking 2.0.x (`anomalyco/opencode` on GitHub; same repo
that also ships the older, much more widely-used `@opencode-ai/plugin`
line under the same `opencode` name at 1.18.x — two parallel plugin
API generations in one project, not two separate products). Run
`python3 -m jev_gate.doctor`, which reports the resolved version and
whether it looks like the 2.x line.

**Do not rely on the 1.18.x line for this gate.** Its `permission.ask`
plugin hook has been confirmed dead code since v1.3.0 (see
[anomalyco/opencode#47654](https://github.com/anomalyco/opencode/issues/47654),
open as of 2026-09-20; fix PR
[#47675](https://github.com/anomalyco/opencode/pull/47675) unmerged) —
a plugin registering it loads cleanly and simply never gets consulted,
which is *worse* than the 2.x line's known issues because there is no
error to notice. If a future `opencode` release finally merges that
fix and you want to port this gate to `@opencode-ai/plugin`, treat it
as a rewrite (different Hooks shape, `permission.ask(input, output)`
with `output.status`, no `ctx.event.subscribe`), not a config tweak.

**Community v1 plugins on the 2.x line:** tested against 2.0.11 with
the 12 plugins previously carried in this environment's global config
— 10 fail to load (`PluginModule.LoadError`, wrong Hooks shape for
this API generation): `opencode-notifier`, `oh-my-openagent`,
`opencode-antigravity-auth`, `opencode-gemini-auth`,
`opencode-openai-codex-auth`, `opencode-pty`, `opencode-shell-guard`,
`opencode-supermemory`, `opencode-vibeguard`, `opencode-websearch-cited`,
plus `opencode-worktree` (entrypoint not found, a packaging issue).
Two load fine: `superpowers` (pin `@git+https://github.com/obra/superpowers.git`,
its default branch already ships 2.x support) and `opencode-dcp`.
Don't assume a plugin "should" work on this line just because it's
popular — check the actual load result.

**"It worked on an older opencode 2.x, breaks on the newest one":** the
`@opencode/plugin` SDK package (npm, pinned in `plugin/package.json`)
and the `opencode` CLI binary are versioned independently — a newer
CLI can ship a `permission.asked`/`ctx.session.context` shape the
pinned SDK types don't match, or vice versa. Before filing a bug,
capture the exact runtime version (`opencode --version`) next to the
SDK version, and downgrade via the *direct* installer
(`curl -fsSL https://opencode.ai/v2/install | bash -s -- --version <old>`)
rather than `opencode upgrade <version>` — that command always targets
the single canonical `~/.opencode/bin/opencode`, so if you ever run it
from a renamed/copied binary meant to preserve an old version
side-by-side, it silently overwrites the *canonical* install instead,
not the copy. Keep one install; don't hand-roll a second copy under a
different name to "pin" a version — it doesn't work the way it looks
like it should.

Global `~/.config/opencode/opencode.json`:

- `plugin` — 1.18.x-line plugins (npm names / git specs)
- `plugins` — 2.x-line plugins, this gate among them, as
  `{package, options}` objects. Put the API key in `TYPESAFE_API_KEY`
  (e.g. `~/.config/opencode/secrets.env`, sourced from `.zshrc`), not
  in JSON. That source line only runs in an *interactive* shell — a
  background `opencode service start` launched from a non-interactive
  script/session won't have the key unless you source it first in that
  same shell before starting the service.

Anything else in that config — other `instructions` entries, other
plugins in either list — belongs to whatever else you've installed
globally, not to this gate. Check `plugin/README.md` before assuming an
unfamiliar line came from here.

## Question dialog hangs after picking an option

**Status: under investigation, not confirmed fixed.**

First hypothesis (wrong, reverted): that the plugin's own
`ctx.permission.reply` for `multichoice` was racing the human's answer
for the same `requestID`, so the plugin should never reply for
multichoice. Tried that — it "fixed" the hang by skipping the auto-
approval entirely, which just traded the hang for a mandatory manual
Allow/Reject click before every question. That defeats the point of
the gate (removing exactly that click), so it was reverted. Jev still
approves the tool call for `multichoice` like any other kind; only
`pick` (the recommended answer) is ever a log-only field, never
submitted as the human's choice.

What's actually confirmed and fixed: `setup()` running more than once
per opencode process (same `pid`, different `inst` in the log), causing
duplicate Jev calls and a reply race — first claimant now wins via a
marker claimed *before* calling Jev, so at most one instance evaluates
and replies per `requestID`. This was verified on 2.0.6 to NOT be the
whole story: with a single, clean, successful `jev-allow` reply (no
race, confirmed via the log), the dialog still hung after picking an
option. As of 2026-09-20 the environment moved to 2.0.11 (single
install; see "Which opencode, which version" above) — the hang has not
yet been re-tested on 2.0.11 specifically. Re-run the repro below
before assuming it's still present or assuming it's fixed.

If you hit the hang again after this fix: capture
`tail -5 ~/.local/share/opencode/jev-decisions.jsonl` (or your
configured `JEV_GATE_LOG`) right after it happens, and check
`grep -o '"inst":"[a-z0-9]*"' <log> | sort -u` for more than one value
sharing a `pid` — that would mean the cross-instance claim isn't
covering your setup and is worth reporting with the log line attached.
If the log shows a single clean `jev-allow` with no `reply-failed`
follow-up and it still hangs, the cause is elsewhere (likely opencode
v2's own dialog handling after an async, non-instant permission
approval) and needs a report upstream, not another change here.

**Repro:** `permission: "ask"` (required, see above), plugin enabled,
API key loaded in the service's own environment. Close any running
`opencode` service (`opencode service stop`), start a fresh one from a
shell that has sourced `secrets.env`, open the TUI in a test directory,
send: "Hazme una pregunta multiopción: qué cenamos hoy. Opciones
exactamente: pizza, sushi, ensalada. Usa la herramienta de pregunta del
sistema y espera mi respuesta." Watch for a `"tool":"question"` line
with `gateAction:"allow"` in the log, then pick an option in the
dialog. Success = the agent continues with your pick. This needs a
human at the keyboard; it cannot be scripted (the failure is about
what happens after a real click).

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
