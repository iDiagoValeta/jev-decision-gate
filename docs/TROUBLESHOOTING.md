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
the 12 plugins previously carried in this environment's global config.
Before removing a v1-only plugin, check whether its package ships a
*native* v2 build under an alternate export subpath — `opencode-pty`
does (`opencode-pty/v2`, confirmed via `npm view opencode-pty exports`:
a real `./v2` entry exporting `Plugin.define({id, setup})`), so
`"opencode-pty"` in config becomes `"opencode-pty/v2"`, no code
required on our end. `npm view <pkg> exports` and `main` is the fast
way to check — no `/v2`-shaped alternate export means there's nothing
native to point at.

Checked the same way for the rest: `opencode-notifier`, `oh-my-openagent`,
`opencode-antigravity-auth`, `opencode-gemini-auth`,
`opencode-openai-codex-auth`, `opencode-shell-guard`,
`opencode-supermemory`, `opencode-vibeguard`, `opencode-websearch-cited`
— none ship anything beyond their single v1-shaped default export, so
none can be fixed by pointing at a different entry point. Removed from
config rather than left in erroring; a **hand-written compatibility
shim** (translate v1 Hooks calls into v2 Context calls) was considered
and deliberately not attempted here — three of those are auth plugins
(`opencode-antigravity-auth`, `opencode-gemini-auth`,
`opencode-openai-codex-auth`), and a shim bug in a credential flow is a
much worse failure mode than the plugin simply not loading. `opencode-worktree`
is additionally broken on the publisher's side regardless of API line:
its own `package.json` declares `main: dist/server.js`, a file that
does not exist in what actually got published (`dist/plugin/worktree.js`
is the real entry, but it isn't exposed via the package's `exports`
map either) — nothing to fix from a consumer's config.

What's left after this pass: `superpowers` (pin
`@git+https://github.com/obra/superpowers.git`, its default branch
already ships 2.x support), `opencode-dcp`, and `opencode-pty/v2`.
Don't assume a plugin "should" work on this line just because it's
popular, and don't assume "fails to load" means "needs a shim" — check
`npm view <pkg> exports` for a native build first.

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

**Status: NOT fixed. Three different fixes tried, all failed to
resolve it. Stop and rethink before trying a fourth — see "What we
actually know" below.**

Timeline, in order, because each "fix" was reverted or disproven for a
specific reason and it's worth knowing why before touching this again:

1. **Auto-approve `multichoice` like any other kind** (original
   design). Hangs after picking an option.
2. **Fix: claim the requestID before calling Jev, not just before
   replying**, to close a real cross-instance race (`setup()` runs more
   than once per opencode process — confirmed, was causing duplicate
   Jev calls). Genuine improvement (removed real duplicate work), but
   verified on 2.0.6 to NOT be the cause of the hang: a single, clean,
   race-free `jev-allow` reply still hung after picking.
3. **Skip the reply for `multichoice` entirely** — tried once, reverted
   because it seemed to trade the hang for a mandatory manual
   Allow/Reject click that wasn't there before.
4. Live testing on 2.0.11 showed step 3's objection didn't hold: the
   reply to a `multichoice` permission consistently arrives ~750-900ms
   after the request, after the client has already shown its own
   "Permission required" screen, so it always lands as `"Permission
   request not found"` — the manual click was happening regardless of
   what the plugin did. And with the plugin fully disabled (no reply
   attempted, nothing subscribed at all), picking worked. That looked
   like proof the attempted-and-failed reply call was the corrupting
   factor.
5. **Re-applied fix 3, verified live on 2.0.11 — still hangs.** Jev
   evaluates and logs (`gateAction:"allow"`, no `reply-failed` follow-
   up — confirmed via the log, the fix is genuinely active), the reply
   is never attempted, and picking an option after approving still
   hangs the same way. The "reply attempt corrupts the follow-up"
   theory from step 4 is **wrong**, or at least incomplete.

**What we actually know:**
- Plugin fully disabled (`enabled: false`, zero event subscribers,
  zero session reads, nothing touches this permission at all) →
  picking works, confirmed twice.
- Plugin enabled — even in its most passive form now (evaluates,
  logs, never replies) — picking hangs, confirmed on both 2.0.6 and
  2.0.11.
- The one thing every "enabled" configuration shares, that "disabled"
  doesn't, isn't just the reply attempt (ruled out) — it's `setup()`
  subscribing to the event stream at all (confirmed still running
  twice per process: the log always shows two `inst` values, one
  `duplicate-suppressed`, one that actually evaluates) and calling
  `ctx.session.context({sessionID})` for the same session while its
  interactive tool call is still open. Neither has been isolated as
  the actual cause yet — that's the next thing to test, not fix blind.

**Do not attempt a fourth code change without isolating this first.**
A clean next diagnostic (not yet run): make the plugin do *nothing at
all* for `kind === "multichoice"` — no `objectiveFor`/`ctx.session.context`
call, no Jev spawn, not even a log line, `return` immediately — while
still leaving `ctx.event.subscribe` active (so the double-subscriber
situation stays). If picking still hangs with that, the double
subscription itself is implicated, not anything the handler does. If
picking works, `ctx.session.context` mid-flight is the suspect. Either
result points at something in opencode's own event/session handling
during an interactive tool call, likely worth an upstream report rather
than another patch here.

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
