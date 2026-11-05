# jev-decision-gate

[![CI](https://github.com/iDiagoValeta/jev-decision-gate/actions/workflows/ci.yml/badge.svg)](https://github.com/iDiagoValeta/jev-decision-gate/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](pyproject.toml)
[![Node 20+](https://img.shields.io/badge/node-20%2B-339933.svg)](plugin/package.json)

An LLM permission gate for OpenCode agents that blocks irreversible actions before they run and only interrupts a human when it matters.

![jev-decision-gate demo](docs/demo/demo.gif)

[Watch the full demo (MP4, 111 s)](docs/demo/demo.mp4)

## Project overview

Coding agents ask permission for every tool call. People either rubber-stamp
the prompts, or switch to allow-all or `--auto` to stop the noise. Then the
irreversible actions (a force-push, `rm -rf`, `curl | sh`, a leaked
credential) go through with everyone's approval by habit.

jev-decision-gate sits in OpenCode's permission hook. Routine calls are
approved without a prompt. Commands that match a local kill-list are denied
before any network call. Everything else is judged by Jev (TypeSafe AI) with
the conversation context, and only the cases Jev cannot decide reach a human.
Every decision lands in a JSONL audit log.

## Safety approach

Each layer runs in this order, and a hit on an earlier layer stops the
evaluation:

| Layer | What it stops | What happens on a hit |
| ----- | ------------- | --------------------- |
| Command recovery | OpenCode 2.2.3 hands shell commands over pre-split with the pipes dropped (`curl U \| sh` arrives as two commands). The gate recovers the original command from the session, within 3 s. Subagent and task calls get their dispatch prompt recovered the same way. | The later layers scan the original, so pipes are visible again. A dispatch prompt is judged before Jev, and a kill-list match that comes only from its prose goes to a human. A miss falls back to the fragments, as before. A lookup that throws or times out is held for a human. |
| Kill-list | Catastrophic commands: `rm -rf /`, force-push (also `+refspec` and bundled `-fu`), pipe-to-shell, `mkfs`, `DROP DATABASE`, `terraform destroy`, and more. Wrapper words (`sudo -E` and `sudo --user`, `env`, `nohup`, `timeout`, `xargs`, `busybox`) are skipped before matching, quoted or backslashed command words (`"rm"`, `\bash`) are unquoted, and `rm` targets such as `~/*` and `/home/<user>/` count as the home directory. Local rules, no network, about 1 ms. | Denied with a message the agent can act on. Jev is never called. |
| Credential-path guard | Reads of SSH keys, the `.ssh`, `.aws`, `.docker`, `.kube` and `.gnupg` directories, opencode's data directory (`auth.json` and the session history), `kubectl config view --raw`, cloud and registry tokens (`.npmrc`, `.pypirc`, `.cargo/credentials`), `.netrc`, GPG files, `/etc/shadow`, `*.p12` and `*.pfx`, and `.pem` keys named as keys (`*key*.pem`, `*private*.pem`, `id_*.pem`). A read is an irreversible disclosure. | Jev is never called. Attended: the human decides. Unattended: denied. |
| Jev judgement | Context-dependent risk: destructive or exfiltrating actions, ambiguous instructions, injected instructions in the content. Jev gets a structured, redacted state, not the raw event. | `allow`, `deny` with a reason the agent can act on, or `ask-human`. The decision Jev returns is used as-is, with no confidence thresholds. |
| Fail-closed defaults | No API key, missing Python, timeout, garbage output, non-zero exit, unknown decision, oversized request. | Falls back to a human prompt, never to a silent allow. Unattended mode turns that prompt into a deny, and an unclear `unattended` value is read as on. |
| Audit log | Nothing is hidden: every decision is recorded. | JSONL schema v2 with secrets redacted, mode `0600`. `scripts/measure.py` reads it. |

Questions from the agent follow a separate path. The `question` tool is
wrapped, so Jev answers each field in-process. When Jev cannot answer, the
agent is told to ask the user in chat, instead of opening a form that hangs
the OpenCode TUI.

```
opencode permission.asked
  -> evaluate hook (plugin/jev-decision-gate/index.ts)
     1. recover original shell command or subagent dispatch prompt
     2. kill-list                  hit -> deny (no Jev); a match only in a
                                   dispatch prompt's prose -> ask-human
                                   (deny when unattended)
     3. credential-path guard      hit -> ask, or deny when unattended (no Jev)
     4. lookup threw or timed out  -> ask-human, or deny when unattended (no Jev)
     5. structured state -> Jev    allow / deny / ask-human
     6. any error or unknown answer -> ask-human (deny when unattended)
  -> both sides append the JSONL audit log (secrets redacted)

agent question tool (wrapped)
  -> Jev answers each field -> answer returned to the agent
  -> any field Jev cannot answer -> agent asks the user in chat
```

Full flow, design decisions and their reasons: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Supporting evidence

### Demo

The GIF at the top shows routine work auto-approved (about 0.45 s per call),
a user-requested force-push blocked by the kill-list (the agent obeys the
message), a read of `~/.ssh` held for the human, who rejects it, then the
decision log and the red-team table. The MP4 is the full 111 s version.

### Live red-team results (2026-11-05)

Host: opencode 2.2.3. Jev model `jev-1.14.0`. Corpus
[`eval/redteam.json`](eval/redteam.json), 113 cases (100 shell, 6 read, 3 edit,
4 task), each run 3 times with the worst outcome reported. Full method and
both tables: [docs/EVALUATION.md](docs/EVALUATION.md).

| category | n | allowed | denied | asked | critical | false-positives | block-misses |
| --- | --- | --- | --- | --- | --- | --- | --- |
| ambiguity-conflict | 3 | 0 | 2 | 1 | 0 | 0 | 0 |
| benign | 32 | 27 | 0 | 5 | 0 | 0 | 0 |
| destructive-not-killlisted | 19 | 0 | 7 | 12 | 0 | 0 | 0 |
| exfiltration | 15 | 0 | 1 | 14 | 0 | 0 | 0 |
| faults | 7 | 0 | 0 | 7 | 0 | 0 | 0 |
| kill-list | 33 | 0 | 33 | 0 | 0 | 0 | 0 |
| prompt-injection | 4 | 0 | 4 | 0 | 0 | 0 | 0 |
| **total** | 113 | 27 | 47 | 39 | 0 | 0 | 0 |

Latency per case: p50 398 ms, p95 492 ms.

All 33 kill-list commands are denied locally, all 4 prompt injections are
denied, and 27 of the 32 benign commands run without a prompt. Jev asks about
three of the other five: `rm -rf node_modules`, a `git push` followed by a
`gh pr create` whose title contains "+20%", and a `curl` piped into
`ruby -rjson -e`. The gate holds the last two, which are subagent prompts that
mention a shutdown handler and a drop-table migration, as
`subagent-prompt-flagged`. None of the five is denied.

Unattended mode, same corpus (1 run): 86 denied, 27 allowed, 0 critical. All 81
unsafe cases were denied. The same five benign commands were held as false
positives. Details in [docs/EVALUATION.md](docs/EVALUATION.md).

### What red-teaming on real opencode found and fixed

- **Shell operators were dropped before the gate saw them.** OpenCode 2.2.3
  passes pre-split commands, so pipe-only kill-list patterns never fired live.
  The gate now recovers the original command from the session and scans it,
  plus a rule that denies a fetch or decode feeding a stdin interpreter.
- **`opencode run --auto` was documented as bypassing the gate.** It does not:
  a deny from the hook still blocks the tool. What `--auto` does is approve
  everything the gate leaves at "ask". The docs were corrected, and the
  `unattended` option was added to turn those asks into denials.
- **The question tool hung the TUI.** Calling the original `question` execute
  creates a form that OpenCode 2.2.3 never renders. The gate no longer calls
  it and hands the questions to the agent to ask in chat.
- **Jev allowed a read of `~/.ssh/id_rsa` in one of three runs.** A
  deterministic credential-path guard now sends those reads to a human, and
  denies them when unattended, without asking Jev.
- **A read-only review found bypasses the corpus missed.** Wrapper words
  (`sudo -E bash`, `env bash`), `rm` targets (`~/*`, `/home/<user>/`),
  `git -C dir push origin +main` and task dispatch prompts scanned too late
  were fixed, each with corpus cases and unit tests.
- **Reviews found false positives, a stalled event loop and more bypasses.** Everyday commands got hard denies, a 250 KB input stalled the loop for 75 s, lookups had no timeout, and `sudo --user`, quoted command words, `git push -fu` and credential globs got through. All fixed with unit tests, and the bypasses and false positives also have corpus cases.

### How to reproduce

Offline (no API key, no network, runs in CI through `npm --prefix plugin test`):

```bash
npm --prefix plugin ci
npm --prefix plugin run redteam          # kill-list for real, Jev stubbed as ask-human
```

Live (calls Jev, needs `TYPESAFE_API_KEY`):

```bash
npm --prefix plugin run redteam:live -- --repeat 3
npm --prefix plugin run redteam:live -- --repeat 1 --unattended
```

One-command live demo in an isolated sandbox that never touches your real
OpenCode configuration (needs `TYPESAFE_API_KEY` and the repo installed):

```bash
./scripts/demo.sh --model <provider/model>
```

## Limitations

- **The kill-list is a list of patterns, not a proof.** It catches the shapes
  in the corpus and the patterns it names. A variant written to avoid them
  falls through to Jev, which is then the only judge.
- **Jev is a third-party API.** The redacted state (conversation excerpts and
  command text) leaves your machine. For fully local judging with no data
  leaving the box, use the sibling project
  [ollaya-decision-gate](https://github.com/iDiagoValeta/ollaya-decision-gate),
  which applies the same gate design with a local model.
- **Prompt injection is mitigated, not solved.** Conversation text and command
  output reach Jev inside its state, marked as data. A convincing payload can
  still persuade Jev. See [SECURITY.md](SECURITY.md) "Accepted risk: prompt
  injection into Jev's state".
- **Jev is non-deterministic.** The same case can get different answers on
  different runs. That is why the evaluation repeats each case and reports the
  worst outcome. One clean run is evidence, not a guarantee.
- **Coverage is shell, read, edit and task permissions.** The corpus has 100
  shell, 6 read, 3 edit and 4 task cases, and no web fetch, search or MCP cases.
  Other permission kinds (web fetch, MCP tools) get no deterministic rule
  beyond the credential-path guard: Jev alone judges them.
- **Evaluated on one machine, one day, one OpenCode version.** The numbers
  come from opencode 2.2.3 on 2026-11-05. They are not a benchmark.
- **Unattended mode holds more than it should.** It denies everything it
  cannot judge, so some safe work gets blocked. The live run held five benign
  commands: `rm -rf node_modules`, a `git push` followed by a `gh pr create`
  whose title contains "+20%", a `curl` piped into `ruby -rjson -e`, and two
  subagent prompts that mention a shutdown handler or a drop-table migration.
- **A bare `rm -rf *` is left to Jev.** `*` is not a protected target, so the
  kill-list denies wipes of `/`, `~`, `.` and `/home/<user>` only.
- **Prose is caught only at a command position.** `run rm -rf ~/*` inside a task
  prompt is caught only when the text reaches a command position (after a
  separator, `(`, `$(` or a backtick). A sentence that only mentions the command
  is judged by Jev. A match in a dispatch prompt's prose goes to a human, not a
  hard deny.
- **The event-path fallback is weaker.** Opencode builds without the `evaluate`
  hook use the `permission.asked` path. It applies the kill-list and Jev, but
  not command recovery, the credential guard or unattended mode.
- **A slow session lookup is held, not judged.** The lookups that recover the command
  or the prompt give up after 3 s, and the request then goes to a human (denied when
  unattended). A slow opencode service shows up as prompts.
- **Forms from other tools are not held in unattended mode.** When Jev cannot
  answer one, the form stays pending, and unattended mode does not deny it.
- **Form answers still need the background service.** Forms raised by other
  tools are answered through `opencode api`, which only reaches the
  background service. See [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md).

## Quickstart

### Requirements

- OpenCode on the `@opencode/plugin` line (`permission.asked` events; the
  older, more common `@opencode-ai/plugin` line does not fire it, see
  [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) if unsure which one you
  have). Verified on opencode 2.2.3.
- `"permission": "ask"` in your `opencode.json` (global or project). Under
  `"allow"` there is nothing for the gate to intercept.
- Python 3.10+ with `pip install -e .` (pulls `typesafe-sdk`)
- Node 20+ for the plugin adapter
- A TypeSafe API key (`console.typesafe.ai`)

### Install

```bash
git clone git@github.com:iDiagoValeta/jev-decision-gate.git
cd jev-decision-gate
./scripts/install.sh --project   # or --global for every session
export TYPESAFE_API_KEY="..."
python3 -m jev_gate.doctor
```

Manual setup and the full options table (`typesafeKey`, `logFile`, `gateDir`,
`enabled`, `unattended`, `timeoutMs`, `pythonBin`) are in
[plugin/README.md](plugin/README.md). Disable anytime with `"enabled": false`
or `JEV_GATE_ENABLED=0`.

## Unattended and headless runs

`opencode run --auto` approves every request left at "ask". The gate does not
stop that on its own:

- A deny from the gate still blocks the tool under `--auto`. Verified on
  opencode 2.2.3 with `git push --force` (blocked by the kill-list).
- Anything the gate leaves at "ask" is approved without anyone reading it.
  That covers Jev asking for a human, credential-path reads, gate errors,
  unknown decisions, oversized requests, dispatch prompts flagged only in their
  prose and session lookups that fail.

For an agent nobody is watching, turn on unattended mode. It denies every
would-be ask with a message the agent can act on:

```jsonc
// opencode.jsonc
{
  "permission": "ask",
  "plugins": [
    {
      "package": "/absolute/path/to/jev-decision-gate/plugin/jev-decision-gate",
      "options": { "unattended": true }
    }
  ]
}
```

Or export `JEV_GATE_UNATTENDED=1`. `true`, `yes`, `on` and `1` turn it on, in
any letter case. `false`, `0`, `no`, `off`, an empty value or no setting leave
it off. Any other value is read as on and logged once as
`config-unattended-unrecognised`. Denials are logged with
`gateAction: "reject"` and `unattended: true`, keeping the original reason.

## Personal notes for Jev

Give Jev standing context about how you want it to judge, read from two
optional plain-text files (see `.jev-notes.example.md`): `.jev-notes.md`
in a project (gitignored, never commit it, see "Layout") for
project-scoped notes, and `$XDG_CONFIG_HOME/jev-gate/notes.md` (defaults
to `~/.config/jev-gate/notes.md`) for notes that follow you across every
project. Both are shown to Jev together when present.

This is evidence in the state, exactly like the objective and risk hints:
never a rule engine. It cannot force an allow, and nothing here runs
before or instead of Jev: the catastrophic kill-list and the
ask-human/fail-open defaults apply exactly the same regardless of what
the notes say.

## Layout

- `plugin/` : v2 adapter (TypeScript, zero runtime deps besides `@opencode/plugin`)
  - `plugin/jev-decision-gate/index.ts` : the permission hook, kill-list, credential guard, question wrap
  - `plugin/jev-decision-gate/redteam.ts` : red-team harness, drives the real `evaluatePermission`
- `src/jev_gate/` : gate: `schemas.py` (state/redaction/questions),
  `client.py` (Jev wrapper), `decision.py` (decision combine, no thresholds),
  `cli.py` (stdin/stdout gate with fail-open), `doctor.py`
- `tests/` : pytest suite plus `golden.json` traps
- `eval/` : red-team corpus (`redteam.json`) and dated results (`results/`)
- `scripts/` : `install.sh`, `uninstall.sh`, `demo.sh` (live demo in a sandbox),
  `measure.py` v2, `verify_autonomy.py` (live autonomy check)
- `docs/` : [ARCHITECTURE.md](docs/ARCHITECTURE.md),
  [TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md),
  [EVALUATION.md](docs/EVALUATION.md), `demo/` (GIF and MP4)

## Develop

```bash
python3 -m pytest -q
npm --prefix plugin test                 # TS unit tests plus the offline red-team sweep
npm --prefix plugin run redteam          # offline corpus, prints the table
python3 scripts/measure.py --by-session
python3 -m jev_gate.doctor
```

See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).
