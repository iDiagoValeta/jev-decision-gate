# Architecture

## Flow

Requires `"permission": "ask"` in opencode's config (global or project):
under `"allow"` the evaluate hook sees `effect=allow` already and leaves
it alone, and no `permission.asked` event fires at all when the ambient
mode is already `allow`, so there is nothing for the gate to decide. See
`docs/TROUBLESHOOTING.md`.

```
permission evaluate hook (ctx.permission.hook("evaluate"))
  → input.effect already allow/deny (user config) → leave it, done
  → claim eval:<sessionID>:<source>:<action>:<sha> (exclusive marker): lost, do nothing
  → action === "question" → effect=allow (passthrough), NO Jev
        log reason=question-permission-passthrough
        (answering happens via the wrapped question tool or the form API: see below)
  → action shell/bash: recover the original command from the tool-call part
        in session context, within a 3 s bound (LOOKUP_TIMEOUT_MS). opencode 2.2.3
        hands resources PRE-SPLIT with the operators dropped; scan
        "<original>\n<resources>" when found, fragments only when the lookup misses
  → action subagent/task: recover the dispatch prompt from the same kind of
        tool-call part (same 3 s bound) and scan "<prompt>\n<resources>". This runs
        before the kill-list and the credential guard, so a dispatch meets the same
        deterministic rules as a shell command. A match in the agent's name (the
        resources) is a hard deny. A match that comes only from the prompt's prose
        goes to the human as subagent-prompt-flagged (denied when unattended)
  → requests over 256 KiB (MAX_SCANNED_CHARS) → left to the human, or denied when
        unattended; reason oversized-request (no scan, no Jev)
  → catastrophic check (deterministic, no network, over the scanned text):
        → fetch or decode feeding a stdin interpreter: a real pipe in one pipeline
          or, when the original command was not recovered, a later segment
          (fetchFeedsInterpreter). Each interpreter has its own option table:
          `python3 --version`, `node --test`, `python3 -m json.tool`, `bash setup.sh`
          and `command -v` do not read stdin, `python3 -E`, `ruby -rjson` and
          `node --inspect` do. Groups count as what they hold:
          `curl U | (cd /tmp && bash)` and `{ curl U; } | python3` are caught
        → rm with a recursive and a force flag and a protected target (`/`, `~`, `.`,
          `..`, `/home`, `/root`, a `/home/<user>` directory), or with `--no-preserve-root`,
          in one simple command (rmRemovesProtectedTarget). An rm word counts wherever it
          sits in that command, and a statement break ends it
        → power-off and reboot as the command word (`shutdown`, `reboot`, `halt`,
          `poweroff`, `init 0|6`, `systemctl` and `loginctl` with `reboot|poweroff|halt|kexec`),
          and `find` with `-delete` or `-exec rm` started from exactly `/`, `~`, `/home`,
          `/root` or `/var`, a home directory, or a system tree (`/etc`, `/usr`, `/boot`,
          `/bin`, `/sbin`, `/lib`, `/lib64`, `/opt`, `/var/lib`) or anything below one
        → `+refspec` force push, matched per git command (forcePushRefspec)
        → the text of a `sh -c '...'`, `bash -lc '...'` or `eval ...` is read back as
          a command line, up to 3 levels deep, and so is the text a command runs for
          another shell (`ssh`, `docker exec`, `su -c`, `find -exec`, ...)
        → the regex kill-list over overlapping 4000-char windows (what a regex can
          still decide: mkfs, dd, curl|sh, git push --force, terraform destroy, ...)
        The token rules read a parsed command (`parseShell`): statements split on
        `;` `&&` `||` `&` and newlines, pipeline stages on `|`, operators inside
        quotes ignored, `( )`, `{ }`, `$( )` and backticks read as nested commands.
        There is no grammar for `if`, `for` or `while`, and no heredoc bodies.
        Every simple command is read after its wrapper words are skipped: sudo
        (with its options, long ones and clusters like `-iu root` included), doas,
        env, nice, ionice, timeout, nohup, setsid, command (but not `command -v`,
        which only looks up), exec, time, xargs, stdbuf and busybox. Quotes and
        backslashes in a command word are removed first, so `"rm"` and `\bash` read
        as rm and bash, and `$SHELL` counts as a shell
        → effect=deny + message "Blocked by jev-decision-gate: ... kill-list"
  → credential-path check (deterministic, same scanned text; the list is in the
        credential ADR below)
        → no Jev: attended leaves effect "ask", reason credential-path;
          unattended denies with the hold message
  → lookup failed (the session lookup threw, or passed its 3 s bound; the error
        class is logged)
        → no Jev: attended asks the human, reason context-lookup-failed;
          unattended denies with the hold message
  → kindFor(action, resources, recovered text as an extra resource):
        read | write | destructive
  → objectiveFor(sessionID), 3 s bound (a timeout falls back to the generic
    objective): recent conversation, both roles, redacted,
                              ≤60000 chars default (options.objectiveChars /
                              JEV_GATE_OBJECTIVE_CHARS, max 90000)
  → gateEvent { objective, halt {kind,tool,detail: the recovered command or
                dispatch prompt, sent once without its fragments, redacted,
                head+tail ≤90000 chars; for edits the patches from metadata.files
                are appended, for grep/glob/list the path/include from
                metadata are appended as "path: ..." lines}, context
                {sessionID,risk_hints}, policy }
  → schemas.build_state: structured JSON {untrusted, objective, halt,
        risk_hints, policy, question, user_notes?} fitted to Jev's ~33k-token
        window (budgets 90k/45k/20k chars, next one on max_tokens_exceeded)
  → runGate: spawn pythonBin -m jev_gate.cli (timeout 25s default, max 30s,
        PYTHONPATH=src, minimal env); one retry if the child died from a
        signal or a transient spawn error
      → build_state / build_questions / client.evaluate → Jev (system_one)
      → decision.combine: pass through Jev's decision, no thresholds
  → allow → effect=allow
    deny  → effect=deny + message "Denied by jev-decision-gate (Jev): ..."
            (the agent gets the reason and continues)
    ask-human / any error → effect stays "ask" → opencode emits
            permission.asked and prompts the human; the plugin only logs
            reason=asked-human for it (no Jev, no reply)
            unattended (options.unattended / JEV_GATE_UNATTENDED) → the
            same cases become effect=deny + a hold message naming the
            reason, logged gateAction=reject, unattended=true
  → both sides append v2 JSONL (0600, no secrets)

Fallback (hook API missing, logged reason=hook-unavailable): the older
permission.asked + `opencode api POST .../permission/{id}/reply` path. It applies
the kill-list and Jev only: no command recovery, no credential guard and no
unattended mode, so credential reads there are judged by Jev alone.

question tool (wrapped via ctx.tool.transform)
  → Jev answers each question in-process (multichoice + pick, labels
    redacted on the way out, mapped back to the original label)
  → all answered → the tool returns {output:{answers}, content, metadata}
    itself: no form, no reply API, works in any opencode server
  → any question unanswerable (ask-human, pick not offered, ambiguous,
    no options) or any gate error → the original execute is NEVER
    called (its form hangs the TUI, see ADRs); the tool returns empty
    answers and content telling the agent to ask the user the questions
    in chat and end its turn; unattended instead says no human is
    available, stop and report
    log reason=question-handoff-chat, phase=question-tool

other tools → form (metadata.kind=question), listed at GET /api/form
  → ONE shared 750ms poller per process (not per setup() instance),
    listing each known project directory via
    GET /api/form?location[directory]=<dir> (the bare endpoint only
    lists the service's own directory); at most one tick in flight at
    a time (also listens form.created / legacy question.v2.asked /
    question.asked)
  → claim form:<formID> (same exclusive-marker pattern)
  → objectiveFor (bounded; failures fall back to a short default)
  → for each form field with options: runGate as multichoice (+ pick)
  → allow+valid pick → POST /api/session/{sessionID}/form/{formID}/reply
                        body {"answer":{"q0":"<pick>", ...}}
     log phase=form-answer then reason=question-answered
  → else ask-human, logged; the form stays pending. Unattended mode does not
    hold forms raised by other tools.
```

`pythonBin` resolution: `options.pythonBin` → `JEV_GATE_PYTHON` → newest
mise install under `~/.local/share/mise/installs/python/*/bin/python3` →
`python3`. The spawn sets `PYTHONPATH=<repo>/src` so `typesafe_sdk`
works when the opencode service's `/usr/bin/python3` lacks it.

Live autonomy check (non-interactive, against a running service):
`scripts/verify_autonomy.py`, see `docs/TROUBLESHOOTING.md`.

## Key decisions (ADRs, short)

- **Shared state lives on `globalThis`, not in module scope.** opencode
  loads a separate copy of the plugin module for each `setup()` instance
  (one per project directory). Module-scope "shared" state would give one
  form poller per directory instead of one per process. With
  `globalThis[Symbol.for("jev-decision-gate.shared.v1")]` there is one
  poller per process, shared across all instances. A test imports two
  copies of the module and asserts they share one interval.
- **The question tool is answered inside the tool, and its human
  fallback is chat, never the form.** Wrapping `question`'s `execute`
  returns Jev's pick as the tool result, so no reply has to reach the
  server, and it works outside the background service. When Jev cannot
  answer, the wrapper does **not** call the original `execute`: on
  opencode 2.2.3 that creates the form server-side
  (`GET /api/form` lists it, `metadata.kind=question`) but the TUI
  never renders it and the agent's turn hangs forever. A minimal probe
  plugin reproducing it: `editor.update("question", (t) => { t.execute
  = (input, context) => original(input, context) })` hangs; without the
  wrapper the dialog renders. Root cause is the SDK's promise adapter
  (`promiseExecutor` in `@opencode/plugin/dist/promise/adapter.js`),
  which runs the host Effect in the plugin runtime, so the form event
  never reaches the TUI. A form created from the plugin cannot be
  delivered; an agent chat question can. The form path remains for
  forms raised by other tools.
- **Permissions are decided in the `evaluate` hook, not by replying to
  `permission.asked`.** opencode awaits the async hook; `effect=allow`
  runs the tool with no prompt, `effect=deny` + `message` fails just that
  tool call with the message and the agent continues, and leaving `ask`
  falls through to the normal human prompt. Replying to `permission.asked`
  via `opencode api` always targets the background service, so a
  decision 404s when the plugin runs in any other server; and a bare
  `reject` reply aborts the whole agent turn. The `evaluate` hook avoids
  both. Forms still reply via `opencode api` (there is no form API in the
  plugin context), so form answers still only work in the background
  service.
- **`opencode run --auto` approves whatever the gate leaves at "ask", so
  unattended mode turns those cases into denials.** Verified on opencode
  2.2.3: `--auto` does not override an `effect=deny` from the `evaluate`
  hook (kill-list and Jev denials still block the tool), but it resolves
  every request left at "ask" itself, without waiting for a human. For an
  agent nobody is watching, that turns the gate's "I am not sure" into
  "yes", the opposite of fail-open's intent. `unattended`
  (`options.unattended` / `JEV_GATE_UNATTENDED`) keeps fail-open's
  meaning by changing the fallback: an ask-human, an unknown decision, an
  oversized request or any gate error becomes a deny carrying a message
  the agent can act on, logged as `gateAction=reject` with the original
  `reason`/`error_class` plus `unattended: true`. There is still no hook
  that fires before `--auto` commits, so this is the only lever inside
  the plugin. Opt-in, because an interactive session is better served by
  a prompt than by a denial. The values `true`, `yes`, `on` and `1` switch it on,
  in any letter case, from `options.unattended` or `JEV_GATE_UNATTENDED`. The
  two sources are combined, so either one that is on turns it on. `false`,
  `0`, `no`, `off`, an empty value or nothing set is off. Any other value is
  read as on (the safe direction for an ask) and logged once per setup as
  `config-unattended-unrecognised`, without echoing the value. Forms
  raised by other tools are not held: an unanswered form stays pending.
- **Reply via `opencode api POST`, never `ctx.permission.reply()`.**
  The SDK method proved unreliable for replying to `permission.asked`
  in this environment. `replyPermission` in `index.ts` shells out to
  `opencode api POST /api/session/{sessionID}/permission/{requestID}/reply`,
  mirroring `replyFormAnswer`'s pattern for form answers. This path is
  now only exercised by the `hook-unavailable` fallback, since
  permissions are normally decided in the `evaluate` hook; form answers
  always use it, since there is no form API in the plugin context.
- **Fail-open, never silent allow.** Every `except` maps to
  `ask-human`/`fail-open` with an `error_class` (and, when useful, an
  `error_detail`). Rationale: a broken gate must cost a prompt, not a
  breach. There is no desktop alert on this path; the log is the only
  signal, by design.
- **Two writers, one schema.** Plugin and CLI each log (the CLI sees
  the Jev internals, the plugin sees session/request IDs). Schema v2
  unifies field names so `measure.py` reads both.
- **Two-phase question handling (form API on 2.0.x).** Agent questions
  are split across permission unlock and answering:
  1. `permission.asked` with `action === "question"`, passthrough
     allow with **no** `ctx.session.context` and **no** Jev call. The
     permission phase only unlocks the tool.
  2. The wrapped `question` tool answers in-process when Jev can.
     When it can't (ask-human, pick not offered, ambiguous, no options,
     gate error), it returns `questionHandoffResult`: empty answers and
     content instructing the agent to ask the user in chat and end its
     turn (`reason: question-handoff-chat`). The original `execute` is
     never called, because its form hangs the TUI on 2.2.3 (see the
     question-tool ADR above). Forms raised by other tools still go
     through `GET /api/form` polling (and `form.created` / legacy
     question events), Jev's `pick`, and
     `POST /api/session/{sessionID}/form/{formID}/reply` with
     `{"answer":{"q0":"<pick>"}}`.
- **`kindFor` covers documented OpenCode permission keys.** Mapping
  follows https://opencode.ai/docs/permissions/: read-class
  (`read`, `glob`, `grep`, `external_directory`, `lsp`, `skill`, …),
  write-class (`edit` / `write` / `apply_patch`, `bash`, `task`,
  `webfetch`, `websearch`, …), `doom_loop` → destructive, `question`
  → multichoice (permission path only; see above). Anything else
  fail-opens to ask-human.
- **`curl`/`wget` are destructive only when they act like a write, not
  because they exist.** `DESTRUCTIVE_HINT` used to match a bare
  `curl|wget`, so a read-only `curl -s URL` scored identically to
  `rm -rf /`. `hasDestructiveCurlOrWget` (`index.ts`) looks for: a
  write/output flag (`-o`, `-O`, `--output`, `--remote-name`), a
  body-sending flag (`-d`, `--data*`, `-F`, `--form`, `-T`,
  `--upload-file`, `--json`), a non-GET/HEAD `-X`/`--request` method, a
  redirection to a real file anywhere in the command (`>`, `>>`, but not
  fd duplication like `2>&1` or anything sent to `/dev/null`), a pipe into
  `tee` with a file argument, or another pipeline segment that is an
  interpreter (`sh`, `bash`, `zsh`, `python`, `python3`, `node`, `perl`,
  `ruby`, or any `sudo ...`). OpenCode may hand a piped bash command as
  one resource per segment (`["curl -s URL", "sh"]`) or as a single
  string (`"curl -s URL | sh"`), so every resource is also split on `|`
  before the check. `kindFor` falls to `read` for a fetch that clears
  this check (not the generic write default), and both `kindFor` and the
  risk-hint computation in `evaluatePermission`/`handleOne` call the same
  function, so the two never drift apart. The kill-list is untouched: a
  `curl`/`wget` piped straight into a shell already matches a kill-list
  pattern and is denied before `kindFor` ever runs.

  A flag-by-flag regex misses curl's getopt-style short-flag clustering
  (`-sLo file URL` is `-s -L -o file URL`), which let a write flag bundled
  with harmless ones slip through as a read: the inverse of the bug above,
  a command that DOES write scored as safe. Each short-flag cluster is
  now scanned letter by letter, case-sensitively: lowercase `o` and
  uppercase `O` both mean curl's file-output flag, lowercase `d` is
  `--data`, uppercase `F` is `--form`, uppercase `T` is `--upload-file`;
  none of them share a letter with common boolean flags like `-s`, `-S`,
  `-L`, `-f`, `-I`. `-o`/`--output` take an explicit filename and can
  target stdout with `-` (`curl -o -`, `-so-`, attached or as its own
  token), which is not a write; `-O`/`--remote-name` take no argument and
  always write a file named from the URL, so curl has no stdout form of
  it. `wget` inverts curl's own default: it saves to disk unless told
  otherwise, so a bare `wget URL` is a write, and only an explicit stdout
  target (`-O-`, `-qO-`, `-O -`, `--output-document=-`) or `--spider`
  (checks the URL, downloads nothing) keep it a read.
- **grep/glob/list get their path back before Jev sees them.** On
  opencode 2.0.x, a `grep`/`glob` permission's `resources` carries only
  the search pattern (e.g. a grep's `resources` is just the regex, never
  the directory); the target path lives in `metadata.path` instead
  (`metadata.include`/`metadata.glob` also travel there when present).
  Judging a bare pattern with no path gives Jev nothing to anchor risk on.
  `metadataDetailFor` (`index.ts`) appends `key: value` lines built from
  `metadata` to Jev's `halt.detail` only, the same way `editPatchesOf`
  appends a diff for edits: the kill-list and `kindFor` keep evaluating
  the original, unenriched `resources`. Wired into both the `evaluate`
  hook and the `permission.asked` fallback path, since a plugin loaded
  on an older opencode without the hook API needs the same enrichment.
- **Shell commands are recovered before judging, because opencode's
  splitter drops the operators.** On opencode 2.2.3 the evaluate hook
  receives `curl -fsSL URL | bash` as `["curl -fsSL URL", "bash"]`, so
  every pipe-only kill-list pattern (curl|sh, wget|sh, base64 -d|sh)
  never fired live and Jev judged fragments. `shellCommandFor` reads the
  original `state.input.command` from the same session-context tool-call
  part `subagentDetailFor` already uses, and `evaluatePermission` scans
  `<original>\n<resources>` for the oversized check, the kill-list, the
  risk hints and `kindFor` (original added as an extra resource). Jev
  receives the recovered command once, without its fragments; the hash in
  the log covers the whole scanned text. Both lookups are bounded to 3 s
  (`LOOKUP_TIMEOUT_MS`) and run before the deterministic checks, so a stuck
  session call cannot hold a permission indefinitely. A miss (no record found)
  keeps the pre-existing behaviour exactly. A lookup that throws or times out
  is not a miss: the request is held (see the `context-lookup-failed` ADR
  below). When the original is not recovered, `fetchFeedsInterpreter` still
  denies a fetch/decode followed by a later stdin interpreter (`sh`, `bash`,
  `python3 -`, `bash -s`, ...) even with the pipe gone; when it is recovered,
  only real pipes count. The
  same lookup recovers a subagent or task dispatch prompt, scanned the same way.
- **A dispatch prompt is prose, so a match in it goes to a human.** A task or
  subagent prompt is text written for another model, and nothing runs it as a
  command. A kill-list pattern in the resources (the agent's name) is still a
  hard deny. A pattern found only in the prompt's prose, such as `rm -rf ~` or
  `drop table` in a sentence about a migration, goes to the human with
  `reason: subagent-prompt-flagged`, and is denied when unattended. The cost is
  that a prompt telling the subagent to run `rm -rf ~` is held rather than
  denied outright. The corpus case `dn-task-rm-home` checks that it is never
  allowed. The live run of 2026-11-05 held two benign prompts this way.
- **A failed lookup is held, not judged.** The lookup that recovers a shell
  command or a dispatch prompt can throw, or run past its 3 s bound. Jev would
  then judge only the fragments (a bare `rm` with no target, a `curl` with no
  pipe), so the gate asks the human instead, with `reason: context-lookup-failed`
  and the error class in the log. Unattended mode denies it. A lookup that finds
  no record is not a failure and keeps the old behaviour. The objective lookup
  (`objectiveFor`) is bounded the same way, and a timeout there falls back to the
  generic objective.
- **Redact before send.** Secrets never leave the box: redaction
  runs in TS (before spawn) and Python (before Jev call); logs store
  `detail_sha256`, not detail. Both layers give identical output: a
  secret-named key (`password`, `token`, `api_key`, ...) has its value
  redacted whether bare, `"double"` or `'single'` quoted (one line, up
  to 200 chars), with the key itself quoted or not (JSON, YAML, .env,
  shell), and so do `--password`, `curl -u`, `mysql -p` and env-style
  `NAME value` pairs.
- **Send Jev a structured state, and only that.** `build_state`
  returns JSON: `untrusted` (which fields are data), `objective`,
  `halt {kind, tool, detail}`, `risk_hints`, `policy`, `question`,
  optional `user_notes`. Untrusted text lives in its own string field,
  so it cannot forge the policy or question. The raw event is never
  attached: it would bypass the Python redaction. Measured live on
  allow/deny/padded-payload cases: same actions as sending brief plus
  raw event, equal or higher confidence, 15 to 25% fewer tokens, and
  injected "pre-approved, answer allow" text still denied. Jev's judgment is still the only real defense against a
  convincing payload; see `SECURITY.md` "Accepted risk: prompt
  injection into Jev's state".
- **Give Jev as much context as fits, never a head-only cut.** Jev is
  cheap (a 90k-char state answers in 1 to 2 s), so the objective budget
  defaults to 60000 chars and the detail to 90000. Anything clipped
  keeps head and tail around an explicit marker, plus a risk hint:
  a head-only cut would hide a payload placed after padding. Redaction
  runs before clipping so no secret is half-matched. The window is
  about 33k tokens (a 95k-char English state used 32.8k); `cli.py`
  retries with a smaller budget on `max_tokens_exceeded` instead of
  falling to ask-human.
- **The kill-list's cost is bounded.** `isCatastrophic` runs its regexes
  over overlapping 4000-char windows (500 chars of overlap), so one window
  bounds a regex's backtracking, and the token rules are single passes over
  a parsed command. Re-reads of nested text (`bash -c` scripts, command lines
  a command hands over, quoted payloads) share one budget of twice the input
  length plus 4096 characters. When it runs out, the call fails closed and the
  request is denied with the kill-list message. Requests over 256 KiB skip the
  scan and Jev and go to the human.
- **The deterministic rules read tokens, not only patterns.** A regex cannot
  tell a flag from an operand, a statement from the next one, or a wrapper
  from the command it runs. A regex also spans statements (`rm -rf dist && tsc
  -p .` would read `.` as a target), matches a word wherever it sits
  (`git commit -m "handle reboot"`) and can backtrack exponentially on a long
  script, so the rm, power-off, find and fetch-to-interpreter rules run on a
  parsed command in one linear pass. An `rm` word counts anywhere in its simple
  command (a dispatch prompt is prose around it), never across a statement
  break, and a quoted string is one word.
  `git push --force-with-lease` and `--force-if-includes` stay on the
  kill-list on purpose: they still rewrite remote history.
  `commandTokens` therefore skips leading wrapper words and their options
  before any rule looks at a command, so `sudo -E bash` and `env FOO=1 sh`
  read as the interpreter they run. `rmRemovesProtectedTarget` classifies
  flags per token (any cluster with `r` is recursive, any with `f` is force)
  and reduces each operand to the directory it names: `~/*`, `$HOME/*`,
  `"${HOME}"/*` and `./*` equal `~` and `.`, and `/home/<user>/` equals
  `/home/<user>`. `forcePushRefspec` looks for a `+refspec` only among the
  arguments of a `git push`, after its global options (`git -C dir`,
  `git -c k=v`), so a `+` in another command's argument does not fire. A
  short-flag cluster that holds `f` (`-fu`, `-uf`) is a force push too.
- **A command that runs its argument hands that argument to be judged as a
  command.** `ssh host '...'`, `docker` or `podman exec`, `kubectl exec ... --`,
  `su -c`, `watch`, `flock`, `nsenter`, `chroot`, `find -exec`, a git `!`
  alias, and `echo` or `printf` piped into a shell: the words are read back as
  a command line of their own, and every rule applies to it. Any other quoted
  word that holds whitespace is read for a wipe and a `+refspec` push only, so
  a power-off inside it is not seen. `echo "rm -rf /"` is denied on purpose,
  because the gate cannot tell prose from a command.
- **The shell reader is not a shell grammar, and the gaps are known.**
  `then`, `do` and `else` stay in the first word of their statement, so a
  power-off, a `find -delete` or a fetch into a stdin interpreter other than
  `sh` or `bash` after them is missed (`for h in a; do reboot; done` passes).
  A wipe is still found, since an rm word counts anywhere in its statement. A heredoc body is read one line
  at a time, so a body line that starts with a wipe is denied. A pipe that
  continues on the next line is two statements to the reader, so the fetch
  rule misses it (`wget URL |` then a newline and `python3 -`), while the regex
  still catches `curl URL |` followed by a newline and `sh`.
- **Credential stores are deterministic, not Jev's call.**
  `touchesCredentialStore` scans the same recovered text as the
  kill-list and, for every action except `question`, stops before any
  gate work. A read is not destructive, but it is an irreversible
  disclosure: the private key reaches the agent's model provider, and
  live red-team runs (2026-11-05, three repeats) had Jev allow
  `~/.ssh/id_rsa` in at least one. Attended leaves `effect=ask` (the
  human decides); unattended denies with the hold message, because
  `--auto` would turn that ask into an allow. `.ssh` matches wherever it
  sits. `.aws`, `.docker`, `.kube` and `.gnupg` are also folder names in
  projects (`docker build -f .docker/Dockerfile .`), so as directories they
  match only after a home or root prefix: `~`, `$HOME`, `${HOME}`,
  `/home/<user>`, `/Users/<user>` or `/root`. Both the raw text and its
  normalized form are checked, so quotes or backslashes spliced into a path
  (`~/.s"s"h/id_rsa`) do not hide it.
  It matches credential paths and file names,
  not the word `ssh`: `docs/ssh-setup.md` and a standalone `*.pub` do
  not fire. The list is:
  - the `.ssh` directory, whole, anywhere: the name must end after the word
    (`~/.ssh/config` and `.ssh/id_x` match; `www.ssh.com` and
    `.ssh-agent-notes.md` do not)
  - the `.aws`, `.docker`, `.kube` and `.gnupg` directories, whole, after a
    home or root prefix (`~/.aws/cred*` matches; `./.aws/config` does not, and
    neither does `.dockerignore`)
  - the credential files `.aws/credentials`, `.docker/config.json` and
    `.kube/config`, anywhere (`~/.docker/config.json` matches too)
  - opencode's data directory, `.local/share/opencode` (its `auth.json` and the
    session history)
  - `kubectl config view` with `--raw`, which prints every credential unredacted
  - `.npmrc`, `.pypirc`, `.cargo/credentials` (and `.toml`),
    `.config/git/credentials`, `.git-credentials`, `.netrc`, `.config/gh`
  - `/etc/shadow`, `/etc/sudoers`
  - `*.p12` and `*.pfx`
  - `.pem` files named as keys only (`*key*.pem`, `*private*.pem`, `id_*.pem`), so a CA bundle such as `ca.pem` is not matched
  - `id_rsa`, `id_ed25519` and `id_ecdsa`
- **Option labels are capped and redacted too, not just OBJECTIVE/
  detail.** `labelsFromFormField` (`index.ts`, question-tool multichoice
  options) feeds Jev's `"pick"` criteria with attacker-reachable label
  text, so each label is redacted and capped at 200 chars
  (`normalizedLabel`). Whatever Jev picks must still be one of the
  attacker's own pre-supplied options, checked independently on both the
  TS (`labels.includes`) and Python (`choice not in options`) sides.
  `valueForPick` re-derives the same normalization at lookup time
  (rather than assuming a positional mapping) so a truncated/redacted
  pick still round-trips to its real underlying value.
- **Form answers honor field types and visibility, not just
  multichoice picks.** In `handleFormAsked`, a `multiselect` field's
  reply value is an **array** of the picked option values
  (`{"answer":{"q0":["pizza"]}}`) rather than a string; `hidden`/`when`
  conditions gate each field against the answers already decided
  (`fieldVisible`, `eq`/`neq` compared with `===`; an unreferenced key
  ⇒ `eq` false / `neq` true), and a not-visible or unanswerable field
  (no options, non-multiselect type) is omitted from the reply; the
  server 400s on a reply that includes a field whose `when` isn't
  satisfied. Every early exit from the field loop logs a distinct
  `reason` (`form-jev-not-allow`, `form-pick-not-offered`,
  `form-pick-ambiguous`, `form-unsupported-field`, `form-field-hidden`)
  with `fieldKey` instead of returning silently; any aborting reason
  leaves the form pending for the human, same as any other ask-human.
- **The event-subscription loop is sequential, by construction.** The
  `for await (const event of ctx.event.subscribe(...))` loop
  (`index.ts`) is a plain pull-based async iterator: `await
  handleOne(...)` for one permission blocks the loop from starting the
  next event (of any kind) until that gate round-trip finishes (up to
  `timeoutMs`, 25s default/30s max). Under concurrent load, later
  simultaneous permissions queue behind earlier ones. This also means
  `inFlight`'s "concurrent duplicates await the same promise" branch is
  currently unreachable (only one requestID can occupy it at a time by
  construction): dead code, not incorrect, kept because parallelizing
  event dispatch would touch the dedup/claim logic directly and needs
  its own dedicated review. `resolved`/`endedSessions`/`formSeen` are
  bounded (`capped()`, 2000 entries, clears rather than tracking
  per-entry age) to prevent unbounded growth.
- **Jev decides, no thresholds.** The winning action is whatever
  Jev's `decision` answer says, at any confidence. Safe/risk answers
  are evidence, not vetoes. Unknown strings and errors still degrade
  to ask-human; catastrophic patterns never reach Jev.
- **One evaluation per request, claimed before calling Jev.** The
  server may emit the same permission request more than once while
  pending, and `setup()` runs more than once per opencode process: two
  independent plugin instances can receive the same event. An exclusive
  marker file (`.jev-gate-replied/<requestID>`) is claimed at the top of
  `handleOne`, before any Jev call: the loser skips entirely (no Jev
  call, no reply attempt), the winner evaluates and replies once. Form
  answers use the same pattern with a `form:`-prefixed claim key. Within
  one instance, in-flight sharing plus a resolved cache also dedupe
  cheaply; late duplicates log `duplicate-suppressed`, except on the
  form path, where a losing claim logs nothing at all (with many sibling
  instances racing every form, losing is the expected outcome, not an
  event worth a log row).
- **One shared form poller per process, listing per project directory.**
  Each `setup()` instance would otherwise start its own 750ms
  `opencode api GET /api/form` interval, one per project directory in
  the process. Module-level state (`registerPoller`/`unregisterPoller`,
  exported for tests) means the first instance starts the single
  interval and later ones only register their handler; the last cleanup
  stops it. Each `setup()` also registers its own `ctx.location.directory`
  (refcounted, removed on cleanup) and every tick lists each known
  directory via `GET /api/form?location[directory]=<dir>`
  (`formListPath`, encoded with `encodeURIComponent`): the bare
  endpoint only lists the service's own directory. With no known
  directory it falls back to the bare endpoint. At most one tick runs at
  a time (a still-running tick skips the next one) so slow listings
  can't stack processes. The tick uses any one registered handler's ctx
  (`session.context` is a process-wide RPC).
- **Single-writer log.** The plugin logs every decision; the Python
  gate stays silent when spawned by the plugin (`JEV_GATE_CLI_LOG=0`)
  and logs only in standalone use.
- **Bounded multi-turn context, not unbounded history.** `objectiveFor`
  sends recent conversation turns from both the user and the assistant
  (assistant text only, tool-call payloads are skipped), newest-first
  until a char budget is hit, so Jev can judge whether a halt matches
  what the agent has actually been doing, not just the human's last
  message. The budget (`objectiveChars` / `JEV_GATE_OBJECTIVE_CHARS`,
  default 60000, clamped to 200 to 90000) fills most of Jev's window;
  `schemas.py` does the final fit. The form-answer path
  uses a tighter budget (and tolerates `objectiveFor` failure) so a
  stuck context call does not block answering.

## Files

| File | Owns |
| ---- | ---- |
| `plugin/jev-decision-gate/index.ts` | hook, catastrophic, kind, objective, question tool wrap, form API poll/reply, spawn (`pythonBin`/mise/`PYTHONPATH`), log |
| `src/jev_gate/schemas.py` | structured state, redaction, questions |
| `src/jev_gate/client.py` | SDK wrapper, usage passthrough |
| `src/jev_gate/decision.py` | decision combine, no thresholds (pure, fully tested) |
| `src/jev_gate/cli.py` | stdin/stdout, v2 log, fail-open map |
| `src/jev_gate/doctor.py` | diagnostics |
| `scripts/measure.py` | rates, p95, cost, by-session |
| `scripts/verify_autonomy.py` | live non-interactive autonomy check |
