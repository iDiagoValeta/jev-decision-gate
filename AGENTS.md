# AGENTS.md

Context for coding agents working in this repo. Humans: see `README.md`
and `docs/ARCHITECTURE.md` instead.

## What this is

An OpenCode **v2** plugin (`plugin/jev-decision-gate/`) that intercepts
`permission.asked` events and asks Jev (TypeSafe AI, via `src/jev_gate/`,
a Python package spawned as a subprocess) to decide allow/deny/ask-human
instead of always prompting a human. Two languages, one flow:

```
opencode v2 → index.ts (permission.asked) → spawn python3 -m jev_gate.cli
            → schemas.py builds the Jev brief → client.py calls Jev
            → decision.py combines the answer → cli.py prints JSON
            → index.ts replies to opencode (or stays silent → human prompt)
```

Full flow and ADRs: `docs/ARCHITECTURE.md`. Read it before touching the
gate logic — the "why" for each design choice lives there, not here.

## v2 only, and beta

This gate targets the `@opencode/plugin` API line (the one with
`permission.asked` events), installed as plain `opencode`, currently
2.0.x. That line and the older, much more widely-used
`@opencode-ai/plugin` line (1.18.x) ship from the same
`anomalyco/opencode` repo as two parallel plugin API generations, not
two separate products — but they are NOT interchangeable and a given
install is one or the other, never both under the same binary.

**Do not "simplify" by porting this gate to the 1.18.x line.** Its
`permission.ask` hook is confirmed dead code since v1.3.0 (see
`docs/TROUBLESHOOTING.md` for the issue links) — a plugin using it
loads cleanly and is simply never called. As of 2026-09-20 this
environment runs a single `opencode` install (2.0.11) after removing
several redundant/stale installs (a separate `opencode-v2` binary copy,
a pnpm global `opencode-ai@1.18.25`, a stale `~/.opencode/bin/opencode`,
a desktop app) that had accumulated across sessions — keep it that way;
don't hand-copy a binary under a new name to "pin" a version (see
TROUBLESHOOTING for why that breaks the canonical install instead).

**`"permission": "allow"` in opencode.json means the gate does
nothing.** Confirmed on 2.0.11: no `permission.asked` event fires at
all when the ambient mode is already `allow` — there is nothing to
intercept. The config (global or project) must set
`"permission": "ask"` for Jev to ever get consulted. If a fresh install
"does nothing" with no errors, check this first.

The `@opencode/plugin` SDK package version (`plugin/package.json`) and
the `opencode` CLI binary version are independently numbered — pin the
SDK explicitly (already done) and treat "it broke on the newest 2.x" as
plausible; verify the actual runtime version before assuming a plugin
bug.

## Layout

| Path | Owns |
| ---- | ---- |
| `plugin/jev-decision-gate/index.ts` | opencode hook: catastrophic-pattern kill list, `kindFor`, conversation-context gathering, spawn, cross-instance dedup, logging |
| `src/jev_gate/schemas.py` | Jev prompt brief, redaction, question shapes |
| `src/jev_gate/client.py` | TypeSafe SDK wrapper, error mapping |
| `src/jev_gate/decision.py` | pure allow/deny/ask-human combine logic (fully unit tested) |
| `src/jev_gate/cli.py` | stdin/stdout contract with `index.ts`, v2 JSONL log |
| `src/jev_gate/doctor.py` | install diagnostics, no secrets printed |
| `scripts/measure.py` | reads the JSONL log: rates, p95, cost, by-session |
| `tests/golden.json` + `tests/test_golden.py` | policy regression traps — a decision-logic/kind change without a new case here is unreviewed |

## Non-negotiables (see `CONTRIBUTING.md` "Safety contract")

1. **Fail-open to `ask-human`, never silent `allow`.** Every `except` in
   the Python gate and every catch in `index.ts` must degrade to
   ask-human with a logged `error_class`, not swallow the error.
2. **No secrets in logs or in the Jev payload.** Both `index.ts`
   (`redactSecrets`) and `schemas.py` (`redact_secrets`) redact
   independently, before send and before log — a change on one side
   without the other is a gap. `pytest -q` has redaction coverage.
3. **Policy changes need a golden case.** Anything touching
   `decision.py`'s combine logic or `kindFor` needs a new entry in
   `tests/golden.json`.
4. **Jev approves the tool call for `multichoice` too — never make it a
   manual click.** The whole point of the gate is removing the
   Allow/Reject click; exempting the tool that asks it most defeats
   that (tried it, reverted, see `CHANGELOG.md` 2026-09-20). `pick` is
   log-only and must never be submitted as the human's actual answer —
   v2 `reply` has no field for it anyway.
5. **`setup()` runs more than once per opencode process.** Confirmed in
   production logs (same `pid`, different `inst`). Any new code path
   that evaluates or replies to a `permission.asked` event must claim
   the requestID first (see `claimReply` in `index.ts`) — assume you are
   racing a sibling instance, not assume you're the only handler.

## Commands

```bash
python3 -m pip install -e ".[dev]"   # Python deps
npm --prefix plugin install           # TS deps

python3 -m pytest -q                              # Python tests
ruff check src tests scripts                       # lint (pyflakes+pycodestyle only, see pyproject.toml)
npm --prefix plugin exec --no -- tsc --noEmit -p plugin/jev-decision-gate   # TS typecheck (no TS unit tests exist)

python3 -m jev_gate.doctor            # install/env diagnostics
python3 scripts/measure.py            # read the decision log
```

CI (`.github/workflows/ci.yml`) runs `pytest` on 3.10-3.12, `ruff`, and
`tsc --noEmit`. There is no automated test for `index.ts` logic beyond
the type check — the interactive permission/dialog flow can only be
verified by hand against a live opencode v2 session (see
`docs/TROUBLESHOOTING.md`).

## Documentation is not optional

Any change that touches behavior, a supported version, a config
requirement, or a known limitation MUST update the relevant doc in the
same change: `docs/ARCHITECTURE.md` (flow/ADRs), `docs/TROUBLESHOOTING.md`
(symptoms/fixes), `CHANGELOG.md` (`[Unreleased]`), and this file when
the fact belongs here. A fix that works but isn't documented is not
done — the next session (human or agent) will rediscover the same dead
end from scratch, as happened repeatedly in this repo's own history
(the opencode-v2/opencode-ai confusion, the dead `permission.ask`
hook, the `permission: allow` no-op) before it got written down.

## Where development artifacts go

Iteration logs, working plans, specs written for an agentic dev
workflow (e.g. superpowers plans/specs), scratch notes — anything that
records *how* the project got built rather than *what it currently is*
— goes in `.dev/` at the repo root, which is gitignored. Never commit
this kind of file under `docs/` or the repo root: `docs/` is what a
contributor reads to understand the current system, and process notes
mixed in there read as confusing clutter, not documentation (this repo
shipped `docs/superpowers/plans/` and a root `ITERATION.md` publicly
for a while before this was fixed).

- Still being added to across sessions (e.g. an ongoing round/iteration
  log) → keep it in `.dev/`, don't delete it.
- Served its purpose and is superseded by real docs (e.g. an initial
  design spec once `docs/ARCHITECTURE.md` covers the current design) →
  delete it outright, don't archive it. `git log` already has the
  history if anyone needs it.

## Before claiming a plugin-side fix works

`index.ts` changes cannot be verified by `tsc` alone — it only proves
the code compiles. The actual behavior (does the dialog still hang, did
the reply race disappear) requires running opencode v2 interactively
and checking the JSONL decision log (`JEV_GATE_LOG` / default
`decisions-plugin.jsonl`) for the real `inst`/`pid`/`gateAction`
sequence. Don't report an `index.ts` fix as done from a green `tsc` run
alone.
