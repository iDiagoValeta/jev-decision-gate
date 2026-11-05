# Troubleshooting

## `opencode run --auto` approves whatever the gate leaves at "ask"

On opencode 2.2.3, `--auto` does not override a deny from the plugin's
`evaluate` hook: a kill-list or Jev denial still blocks the tool (`git push
--force` under `--auto` was blocked in the 2026-11-05 runs). What `--auto`
does is resolve every request the gate leaves at "ask" on its own, without
waiting for a human. In attended mode those are the cases Jev sends to a
human, credential-path reads, gate errors (missing key, timeout, garbage
output), unknown decisions and oversized requests. Under `--auto` all of them
are approved.

Fix: turn on unattended mode for any run nobody is watching. It denies each
would-be ask with a message the agent can act on, and logs it as
`gateAction: "reject"` with `unattended: true` and the original `reason`:

```jsonc
// opencode.jsonc
{
  "plugins": [
    {
      "package": "/absolute/path/to/jev-decision-gate/plugin/jev-decision-gate",
      "options": { "unattended": true }
    }
  ]
}
```

or export `JEV_GATE_UNATTENDED=1`. Check the log after a run: a shell command
with `gateAction: "allow"` or `"ask-human"` and no `unattended` field, from a
session started with `--auto`, means the option was not set in that process.

Evidence (2026-11-05, opencode 2.2.3, unattended live run): all 73 unsafe
corpus cases denied, none allowed. See [EVALUATION.md](EVALUATION.md).

## "It never asks Jev, I always get the manual prompt"

That IS the fail-open design — but find out why:

```bash
python3 -m jev_gate.doctor      # "log writable (<path>)" is the log the plugin writes
python3 scripts/measure.py      # same path, printed as log=<path>
tail -5 <that path>
```

| Symptom in log | Cause | Fix |
| -------------- | ----- | --- |
| `reason: fail-open, error_class: missing-key` | no API key | `export TYPESAFE_API_KEY=...` (must be set in the *service's* env — see below) |
| `error_class: transport` / `missing-sdk` | `typesafe-sdk` missing on the Python the plugin spawns (often the service's `/usr/bin/python3`) | `pip install -e .` into that env, or set `pythonBin` / `JEV_GATE_PYTHON` to a mise/user interpreter (plugin also auto-detects mise and sets `PYTHONPATH=src`) |
| `error_class: gate timeout` | Jev slow / offline | raise `timeoutMs` (max 30000) |
| no log lines at all, `permission: "allow"` in config | no `permission.asked` fires at all when the ambient mode is already `allow` — nothing to intercept | set `"permission": "ask"` (global or project config); that's what lets the gate substitute Jev for the human in the first place |
| no log lines at all, `permission: "ask"` already set | hook never fired for another reason | check `opencode debug config` resolves your plugin path; re-check with `python3 -m jev_gate.doctor` |
| `reason: catastrophic-pattern` | command matched kill-list | intended: rewrite the command |
| `reason: credential-path` | the command or edit touches a credential store (SSH keys, cloud tokens, `.netrc`, ...) | intended: Jev is not consulted; attended, the prompt is yours; unattended, denied |

## Which opencode, which version

This project only works on the `@opencode/plugin` API line (the one
with `permission.asked` events) — installed as plain `opencode`,
verified on opencode 2.2.3 (2026-11-05). The SDK types are pinned to `@opencode/plugin` 2.1.4, whose tool adapter is identical in 2.2.3 (`anomalyco/opencode` on GitHub; same repo
that also ships the older, much more widely-used `@opencode-ai/plugin`
line under the same `opencode` name at 1.18.x — two parallel plugin
API generations in one project, not two separate products). Run
`python3 -m jev_gate.doctor`, which reports the resolved version and
whether it looks like the 2.x line.

**Do not rely on the 1.18.x line for this gate.** Its `permission.ask`
plugin hook is dead code — a plugin registering it loads cleanly and
simply never gets consulted, which is *worse* than the 2.x line's known
issues because there is no error to notice. If a future `opencode`
release finally fixes that and you want to port this gate to
`@opencode-ai/plugin`, treat it as a rewrite (different Hooks shape,
`permission.ask(input, output)` with `output.status`, no
`ctx.event.subscribe`), not a config tweak.

**Community v1 plugins on the 2.x line:** before removing a v1-only
plugin, check whether its package ships a *native* v2 build under an
alternate export subpath (`npm view <pkg> exports` and `main` is the
fast way to check) — no `/v2`-shaped alternate export means there's
nothing native to point at, and the plugin should be removed from
config rather than left erroring. A hand-written v1→v2 compatibility
shim is deliberately avoided for auth plugins in particular: a shim bug
in a credential flow is a much worse failure mode than the plugin
simply not loading.

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
different name to "pin" a version.

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

## Question dialog: how auto-answer works, and what to check if it hangs

The question tool is answered in-process:

**In-process (always).** The plugin wraps the `question` tool's
`execute`. Jev evaluates the offered options and returns a pick; the
wrapped tool returns that pick as the tool result directly, no form,
no reply API, works in any opencode server. Log lines show
`phase: "question-tool"`, `reason: "question-answered"`.

**When Jev can't answer** (ask-human, pick not offered, ambiguous, no
options, or a gate error), the wrapper returns a handoff result:
`answers` is one empty array per question and `content` tells the agent
to ask the user the questions directly in chat, then end its turn
(`reason: "question-handoff-chat"`, `phase: "question-tool"`). With
`unattended` the content instead says no human is available: do not
guess, stop and report. No answer is ever invented.

**Why not the form (root cause).** Calling the built-in `execute`
creates the form server-side (`GET /api/form` lists it,
`metadata.kind=question`) but the TUI never renders it and the agent's
turn hangs forever. Reproduced on opencode 2.2.3 (TUI, both
`--standalone` and the background service) with a minimal wrapper that
only does `return original(input, context)`; without any wrapper the
dialog renders. The cause is the SDK's promise adapter
(`promiseExecutor` in `@opencode/plugin/dist/promise/adapter.js`),
which runs the host Effect in the plugin runtime, so the form event
never reaches the TUI.

**Forms from other tools** still exist. The plugin polls `/api/form`
(and also listens for `form.created` / legacy `question.v2.asked` /
`question.asked`), evaluates each field with options as multichoice,
and on an allow+valid pick POSTs
`opencode api POST /api/session/{sessionID}/form/{formID}/reply`
with body `{"answer":{"q0":"<pick>"}}`. Log shows
`phase: "form-answer"` then `reason: "question-answered"`. If Jev
returns ask-human / invalid pick / reply failure, the form stays
pending, logged, and the human answers in the TUI.

Separately, `permission.asked` for `action === "question"` is always a
passthrough allow with **no** `ctx.session.context` and **no** Jev call
(`reason: "question-permission-passthrough"`) — this only unlocks the
tool call; it never answers the question itself.

**Field-level behavior on the form path:**

- `multiselect` fields are answered with an **array** of the picked
  option values, not a string: `{"answer":{"q0":["pizza","sushi"]}}`.
  Jev returns a single pick today, so the array normally has one
  element; if a future Jev version returns a list of picks, each one is
  mapped to its option value and the array grows accordingly.
- `hidden: true` fields are never answered. A field with
  `when: [{key, op: "eq"|"neq", value}]` is answered only when **all**
  conditions hold against the answers already decided for earlier
  fields, compared with `===` (no coercion — a numeric `value` won't
  match a string answer, which is the safe direction). An
  unreferenced `key` counts as unanswered: `eq` is false, `neq` is
  true. A not-visible field is **omitted from the reply entirely** —
  the server 400s on a reply that includes a field whose `when`
  isn't satisfied.
- A visible field with **no options and a non-multiselect type**
  (boolean / number / free-string) can't be answered by a pick — Jev
  is not called for it. If it's not `required` it's skipped and the
  rest of the form is still auto-answered; if it is `required` the
  whole form stays pending for the human.

**Logged reasons inside the form field loop (no silent exits):**

Every early exit while walking a form's fields logs a line with
`tool: "question"`, `requestID` = formID, `fieldKey`, and one
distinct `reason` (all `gateAction: "ask-human"` — the field/form
stays pending for the human):

| reason | meaning |
| ------ | ------- |
| `form-field-hidden` | conditional field not visible (skipped; form continues) |
| `form-unsupported-field` | visible, no options, non-multiselect type; includes `required` (skipped if false, aborts the form if true) |
| `form-jev-not-allow` | Jev didn't `allow`, or returned no / empty / non-string pick |
| `form-pick-not-offered` | pick not among the offered labels |
| `form-pick-ambiguous` | `valueForPick`/`encodeAnswer` resolved to null (labels collide after redaction/truncation) or several picks landed on a single-select field |

If a question hangs with no click available: confirm the permission
phase logged `question-permission-passthrough` (no Jev call on that
requestID), then look for `phase: "question-tool"` with
`reason: "question-handoff-chat"`: that means Jev declined and the
agent was told to ask in chat instead of opening a form. A form that
never renders after `original` was called is the 2.2.3 bug described
above, not an answering-logic hang. No log line at all for a given form
usually means its project directory never registered with the shared
poller (see "High idle CPU" below). `scripts/verify_autonomy.py`
automates a non-interactive check of this whole path against a running
service.

**Repro:** `permission: "ask"` (required, see above), plugin enabled,
API key loaded in the service's own environment. Open a TUI session in
a test directory and send: "Hazme una pregunta multiopción: qué
cenamos hoy. Opciones exactamente: pizza, sushi, ensalada. Usa la
herramienta de pregunta del sistema y espera mi respuesta." Success:
either `phase: "question-tool"` with `reason: "question-answered"`
(no form at all), or `reason: "question-handoff-chat"` (the agent asks
you in chat); the turn never hangs on a form.

## Ordinary permission replies (`read`/`edit`/`bash`/...) and "Permission request not found"

Permissions are decided in the `evaluate` hook (see
`docs/ARCHITECTURE.md` "Key decisions"), not by replying to
`permission.asked`, so a `reply-failed` on a permission now only
appears on the `hook-unavailable` fallback path. Form answers still go
through `opencode api`, so a form answer attempted in any server other
than the background service still gets `form-reply-failed ... 404`
(the background service is the only server `opencode api` reaches).

If you do see `reply-failed` on the fallback path, or `form-reply-failed`
on the form path: confirm which server the plugin is running in
(`opencode api` always targets the background service), and check
`GET /api/session/{id}/permission` (or `/api/form`) directly to see
whether the request is still pending server-side before assuming a
timing issue.

## A denied tool call ended the whole session

A bare `reject` reply aborts the agent's whole turn ("The user
declined this tool call"). The `evaluate` hook's deny always carries a
`message` (`Blocked by jev-decision-gate: ...` for the kill-list,
`Denied by jev-decision-gate (Jev): ...` for Jev), so only that tool
call fails, and the agent sees why and continues. If you see
`aborted` after a deny, check the log for `hook-unavailable`: you are
on the reply fallback, where a bare reject is possible.

## `fail-open` with `gate killed by SIGKILL`

The gate subprocess died from a signal (OOM killer, a stray `pkill`).
It is retried once automatically (`retry: 1` in the log line). Only a
second consecutive death, or a timeout, falls open to ask-human.

## High idle CPU / a storm of `opencode api GET /api/form`

**Symptom:** many `opencode` CLI processes visible in `htop`/`ps` and
noticeable idle CPU with no active session.

**Design:** there is a single module-level poller per process
(`registerPoller`/`unregisterPoller` in `index.ts`, shared via
`globalThis` since each `setup()` instance loads its own copy of the
module): the first `setup()` instance starts it, the rest only
register, the last cleanup stops it, and at most one tick runs at a
time. If you see one poll process per project directory instead of one
per opencode process, the shared state is not actually being shared —
check it lives on `globalThis`, not in module scope.

The bare `GET /api/form` only lists the service's own directory
(typically the user's home directory), so the poller lists each known
project directory explicitly via
`GET /api/form?location[directory]=<dir>`. A question form in a
project that is never auto-answered (no `phase: form-answer` line at
all, not even ask-human) means its directory never registered with the
poller — check the service actually has that project open.

On the form path, a losing cross-instance claim logs nothing at all
(not even `duplicate-suppressed`) — with many sibling instances racing
every form, losing is the expected outcome and not worth a log row.
`duplicate-suppressed` in the log means the permission (fallback) path
only. `scripts/measure.py` excludes it from rates either way.

## Question answered without any form (`phase: question-tool`)

The plugin answers the `question` tool inside the tool call by default:
log lines with `phase: "question-tool"` and `reason: "question-answered"`,
and no form is created at all. If Jev can't answer (for example a
free-text question has no options, logged as `form-unsupported-field`),
the tool returns the chat handoff (`reason: "question-handoff-chat"`)
and the agent asks you directly in the conversation; no form is
created, so a form never hangs the TUI.

## Which log file?

Canonical: the path in `logFile` / `JEV_GATE_LOG`, default
`<repo>/decisions-plugin.jsonl`. `measure.py` resolves the log in
order: `--log` flag (if given), then `JEV_GATE_LOG` env, then
`logFile` from `~/.config/opencode/opencode.json` (looks in the
`plugins` array for an object whose `package` contains
`jev-decision-gate` and uses `options.logFile` if present — tolerates
a missing file or invalid JSON and falls through). The first source
found is the only one read; the `decisions-plugin.jsonl` /
`decisions.jsonl` cwd files are read only when none is configured. The
resolved path is printed as `log=<path>` (and included as `log` in
`--json` output). The config path can be overridden with
`OPENCODE_CONFIG_FILE` for tests. `scripts/verify_autonomy.py` reads the
log the plugin writes (`JEV_GATE_LOG`, else config `logFile`, else
`<repo>/decisions-plugin.jsonl`) and drives the session with
`JEV_VERIFY_MODEL` (default `opencode/nemotron-3-ultra-free`). It does
not truncate the production log; it saves the log's byte size at start
(or 0 if absent) and in its poll loop reads only new bytes via
`open("rb").seek(offset).read().decode()`.

## Key hygiene

Prefer env (`TYPESAFE_API_KEY`) over `typesafeKey` in JSON (which sits
in cleartext on disk). The key is never logged; `doctor` only prints
whether it is set.

## Still stuck?

Open a bug issue with the template: version, env, redacted log lines,
repro steps. Expectation is always fail-open to ask-human.
