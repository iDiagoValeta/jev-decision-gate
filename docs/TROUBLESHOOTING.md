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
| `error_class: transport` / `missing-sdk` | `typesafe-sdk` missing on the Python the plugin spawns (often the service’s `/usr/bin/python3`) | `pip install -e .` into that env, or set `pythonBin` / `JEV_GATE_PYTHON` to a mise/user interpreter (plugin also auto-detects mise and sets `PYTHONPATH=src`) |
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

**Status (2026-09-21, OpenCode 2.0.11):** live-verified that the
**form reply** path unblocks the question tool and the agent
continued (`ELEGIDO=pizza`, idle succeeded). That is **not** a claim
that every hang case is fixed for all configs — only that auto-answer
via `POST .../form/.../reply` worked in that repro. Do not mark
broader hang closure from a green `tsc` run alone.

### Current approach (full autonomy — form API)

Two phases, deliberately separating permission unlock from answering.
On 2.0.x the question tool opens a **form**, not a dedicated
`/api/question` surface (older docs that said `question.v2.asked` →
question reply API were wrong for this line):

1. **`permission.asked` for `action === "question"`** —
   passthrough-allow (`permission.reply({ decision: "once" })`) with
   **no** `ctx.session.context`, **no** Jev call. Logged as
   `reason: "question-permission-passthrough"`. Mid-flight
   `session.context` on the permission path was the leading suspect
   after earlier failures; this path avoids it by design.
2. **Form answer** — question tool creates a form
   (`metadata.kind=question`) listed at `GET /api/form`. The plugin
   polls `/api/form` and also listens for `form.created` / legacy
   `question.v2.asked` / `question.asked`. Jev evaluates options,
   returns a `pick`, and the plugin POSTs
   `opencode api POST /api/session/{sessionID}/form/{formID}/reply`
   with body `{"answer":{"q0":"<pick>"}}`. Log shows
   `phase: "form-answer"` then `reason: "question-answered"`. This
   closes the old “pick is log-only” model. If Jev returns ask-human /
   invalid pick / reply failure, the human is alerted
   (`notify-send` + `zenity`) and must answer in the TUI.

**Live evidence (auto-answer):**

- Log: `question-permission-passthrough` → `phase: form-answer` →
  `reason: question-answered`.
- Agent wrote `ELEGIDO=pizza` and reached idle — verified on 2.0.11
  (also exercisable non-interactively with
  `scripts/verify_autonomy.py` against a running `opencode` service).

**Still worth checking (human fallback / other hangs):**

- Force ask-human (no key / Jev unsure) → desktop alert fires; picking
  in the TUI should still work (does **not** hang).
- If the human-pick path still hangs with this build, the hang is
  not solved by form auto-answer alone — fall back to the isolation
  diagnostic below.

### Historical timeline (failed fixes — keep for context)

Each earlier "fix" was reverted or disproven for a specific reason:

1. **Auto-approve `multichoice` like any other kind** (original
   design: Jev + `session.context` on `permission.asked`, reply
   once). Hangs after picking an option. `pick` was log-only.
2. **Claim the requestID before calling Jev, not just before
   replying**, to close a real cross-instance race (`setup()` runs
   more than once per opencode process — confirmed, was causing
   duplicate Jev calls). Genuine improvement (removed real duplicate
   work), but verified on 2.0.6 to NOT be the cause of the hang: a
   single, clean, race-free `jev-allow` reply still hung after
   picking.
3. **Skip the reply for `multichoice` entirely** — tried once,
   reverted because it seemed to trade the hang for a mandatory
   manual Allow/Reject click that wasn't there before.
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
6. **Two-phase question handling via form API** (current, full
   autonomy) — see above. Earlier drafts of this step incorrectly
   targeted a `question.v2.asked` / `/api/question` reply path; live
   2.0.11 uses forms (`GET /api/form` +
   `POST .../form/{formID}/reply`). Auto-answer + agent continue
   **live-verified** on that form path; broader “hang fixed for all
   cases” is **not** claimed.

**What we actually know (pre–full-autonomy evidence):**
- Plugin fully disabled (`enabled: false`, zero event subscribers,
  zero session reads, nothing touches this permission at all) →
  picking works, confirmed twice.
- Plugin enabled under every pre–full-autonomy form tested (evaluate
  + reply; evaluate + never reply) → picking hangs, confirmed on both
  2.0.6 and 2.0.11.
- Shared factors across those “enabled” configs: `setup()`
  subscribing to the event stream (still runs twice per process:
  two `inst` values, one `duplicate-suppressed`) and/or calling
  `ctx.session.context({sessionID})` while the interactive tool call
  is open. Full autonomy removes `session.context` from the
  *permission* path for questions; it does not remove the double
  subscription, and the *answer* path may still call `objectiveFor`
  (with a fallback if it fails).

### Next diagnostic (if human-pick / other cases still hang)

Re-check auto-answer with `scripts/verify_autonomy.py` (or the
keyboard repro below) and capture the JSONL sequence
(`question-permission-passthrough` → `phase: "form-answer"` /
`question-answered` or ask-human).

If human picking still hangs after ask-human fallback:

1. Confirm the permission path truly skipped context (log must show
   `question-permission-passthrough`, no Jev `elapsedMs` on that
   requestID for the permission phase).
2. If it still hangs: isolate whether `ctx.event.subscribe` alone is
   enough — temporarily no-op *all* question/form handling (permission
   passthrough, `/api/form` poll, and form/question event handlers)
   while leaving the subscriber active. Hang with that → double
   subscription / upstream event handling; no hang → something on the
   answer path (e.g. `objectiveFor` during form-answer) is still
   implicated. Prefer an upstream report over another blind plugin
   patch once isolated.

**Repro:** `permission: "ask"` (required, see above), plugin enabled,
API key loaded in the service's own environment. Close any running
`opencode` service (`opencode service stop`), start a fresh one from a
shell that has sourced `secrets.env`, open the TUI in a test directory,
send: "Hazme una pregunta multiopción: qué cenamos hoy. Opciones
exactamente: pizza, sushi, ensalada. Usa la herramienta de pregunta del
sistema y espera mi respuesta."

- Autonomy success = log shows passthrough then `form-answer` /
  `question-answered`, agent continues without a click
  (`scripts/verify_autonomy.py` automates this check).
- Hang check (fallback) = force ask-human, pick manually; success =
  agent continues with your pick.

The human-pick hang case still needs a human at the keyboard; it
cannot be scripted (the failure is about what happens after a real
click).

## Ordinary permission replies (`read`/`edit`/`bash`/...) failed with "Permission request not found" (RESOLVED — was never a timing race)

**Status (2026-09-21, OpenCode 2.0.11): fixed.** Was
[issue #15](https://github.com/iDiagoValeta/jev-decision-gate/issues/15).

**Symptom in log:** `gateAction` matched Jev's real decision
(`jev-allow` / `jev-deny` / `jev-asked-human`), immediately followed by
a second line for the same `requestID`:
`reason: "reply-failed", error_class: "Permission request not found: <id>"`.
Jev decided correctly; the reply never reached the tool call, and if
nothing else resolved the permission the tool call hung indefinitely.

**First theory (2026-09-21, earlier the same day — wrong, kept here so
the dead end isn't rediscovered):** that `ctx.permission.reply()` was
racing a short-lived server-side window (~800ms-1s) that Jev's real
API latency sits at the edge of, and that this was unfixable from the
plugin side without an upstream accommodation. A latency-reduction
mitigation (spawning the gate subprocess before `objectiveFor`'s RPC
instead of after) shipped on this theory and measurably reduced the
failure rate, which looked like confirmation.

**What actually falsified it:** live-testing found a permission whose
reply had just failed with "not found" was **still listed as pending**
via `GET /api/session/{id}/permission` *minutes* later — not garbage
collected, not expired. A manual, raw
`opencode api POST /api/session/{id}/permission/{requestID}/reply` on
that exact still-pending `requestID` **succeeded immediately**. There
is no server-side TTL being raced; the permission stays alive far
longer than ~800ms-1s. The failure was specific to *how* the reply was
sent, not *when*.

**Root cause:** `ctx.permission.reply()` (the `@opencode/plugin` SDK
method, called in-process from the plugin) is unreliable in this
environment in a way the equivalent raw HTTP call is not. The likely
contributing factor is the already-documented "`setup()` runs more
than once per opencode process" behavior (see `claimReply` above): two
live plugin instances / event subscriptions exist, and something about
the SDK method's internal binding to a specific instance/connection
appears to make the reply fail even from the instance that legitimately
won the exclusive-claim race and holds a valid `sessionID`+`requestID`.
Not fully root-caused inside the SDK itself (closed source from this
repo's vantage point) — root-caused enough to know the fix.

**Fix:** stop calling `ctx.permission.reply()` entirely. Reply via
`opencode api POST /api/session/{sessionID}/permission/{requestID}/reply`
instead — a subprocess call (`replyPermission` in `index.ts`), the
exact same pattern `replyFormAnswer` already used successfully for form
answers (which is why the form/question-answer path was never affected
by this bug: it never used `ctx.permission.reply()` to begin with).
Applied at all four call sites that used to call the SDK method: the
catastrophic-reject path, the question-permission passthrough, the
main allow/deny path, and the duplicate-event retry path.

**Re-verified live after the fix:** two stress batches driving ordinary
`read` permissions through concurrent load designed to reproduce the
original failures (parallel session creation + a tight
`GET /api/permission/request` polling loop running throughout) — **17
consecutive successes, 0 `reply-failed`**, `elapsedMs` (Jev's own call
time) ranging 743-1032ms, well past the ~832ms this session originally
(wrongly) treated as a hard deadline. Also re-verified the
question-permission passthrough (now also on `replyPermission`) via a
full live multichoice round trip — passthrough, form-answer, and
`question-answered` all logged correctly with `repliedOk: true`.

**What's still true from the abandoned mitigation:** the spawn-before-
`objectiveFor` latency optimization and the alert-on-`reply-failed`
desktop notification both shipped and are harmless, real improvements
independent of the root cause being different than first thought —
left in place. `reply-failed` should now be rare-to-never; if it
recurs, re-open this investigation from "is the raw API call itself
failing" rather than reassuming a timing race.

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
