import { Plugin } from "@opencode/plugin"
import { spawn } from "node:child_process"
import crypto from "node:crypto"
import fs from "node:fs"
import path from "node:path"
import { fileURLToPath } from "node:url"

// Catastrophic patterns: rejected instantly without calling Jev.
// Checked against a NORMALIZED command string (lowercased, quotes/
// separators collapsed) so trivial obfuscation does not bypass them.
//
// Known, accepted false-positive trade-off (present since quote-stripping
// was added, widened by backslash-stripping): stripping quotes/backslashes
// to defeat obfuscation also means descriptive text that merely MENTIONS a
// dangerous command inside quotes can normalize into something that matches
// — e.g. `echo "talk about rm -rf / here"` or `echo "rm -r\f / in docs"`
// both normalize to a string containing `rm -rf /`. This fails closed (the
// command is rejected, not silently allowed) so it's a usability cost, not
// a security hole, and there is no narrower fix available: restricting
// backslash-stripping to avoid this would reopen the r\m obfuscation bypass
// it exists to close (confirmed — `r\m` has a backslash between two
// letters, same shape as the false-positive case). A real shell parser
// could tell prose from syntax; a regex-based kill-list can't.
const CATASTROPHIC = [
  /\brm\s+(-[a-z]*r[a-z]*f|-[a-z]*f[a-z]*r)\s+(\S*\s+)*(\/(?!\S)|\/\*|~(?!\S)|~\/(?!\S)|\$home(?!\S)|\$home\/(?!\S)|\${home}(?!\S)|\${home}\/(?!\S)|\/home(?!\S)|\/home\/[^/\s]+(?!\S)|\/root(?!\S)|\.(?!\S)|\.\/(?!\S)|\.\.(?!\S)|\.\.\/(?!\S))/,
  /\brm\s+(-[a-z]*r[a-z]*f|-[a-z]*f[a-z]*r)\s+.*--no-preserve-root/,
  /\bmkfs\b/,
  /\bdd\b\s+.*\bof=\/dev\//,
  />\s*\/dev\/(sd[a-z]|nvme\d+n\d+|vd[a-z]|hd[a-z])/,
  /\b(shutdown|reboot|halt|poweroff|init\s+[06])\b/,
  /\bchmod\s+(-R\s+)?777\s+(\/|~|\$home|\${home}|\/home|\/etc|\/usr)/,
  /\bchown\s+-R\s+\S+\s+(\/|~|\/etc|\/usr)/,
  /:\(\)\s*\{\s*:\|\:&\s*\}\s*;/,
  /\bsudo\s+rm\s+(-[a-z]*r[a-z]*f|-[a-z]*f[a-z]*r)\s+/,
  /\bfind\s+\/\S*\s+.*-delete\b/,
  /\bcurl\b.*\|\s*(sh|bash|sudo\s+bash)\b/,
  /\bwget\b.*\|\s*(sudo\s+bash|sh|bash)\b/,
  /\bbase64\s+(-d|--decode)\b.*\|\s*(sh|bash)\b/,
  /\b(powershell|pwsh)\b.*\biex\b/i,
  /\bgit\s+push\b.*--(force|mirror)\b/,
  /\bgit\s+push\b.*\s+(-f)(?!\S)/,
  /\bgh\s+repo\s+delete\b/,
  /\bkubectl\s+delete\b.*--all/,
  /\bterraform\s+destroy\b/,
  /\baws\s+s3\s+rm\b.*--recursive/,
  /\bdocker\s+system\s+prune\b/,
  /\bdrop\s+(table|database)\b/i,
]

const DESTRUCTIVE_HINT = /(^|\s)(rm\s+-rf|sudo|git\s+push|git\s+reset\s+--hard|git\s+clean\s+-fd?|kubectl\s+delete|terraform\s+(apply|destroy)|npm\s+publish|cargo\s+publish|drop\s+(table|database)|curl|wget|docker\s+(rm|system)|aws\s+s3)/i

// Command substitution ($(...) or `...`) can hide a command's real effect
// from both the kill-list and normalizeCommand (neither evaluates it) —
// not blockable by regex, so it's surfaced to Jev as a hint instead.
const COMMAND_SUBSTITUTION = /\$\(|`/

const SECRET_PATTERNS: RegExp[] = [
  /bearer\s+[A-Za-z0-9\-._~+/=]{8,}/gi,
  /basic\s+[A-Za-z0-9+/=]{8,}/gi,
  /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g,
  /\b(ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|sk-[A-Za-z0-9\-_]{8,}|xox[bpas]-[A-Za-z0-9\-_]{8,})\b/g,
  /-----BEGIN [A-Z ]*PRIVATE KEY-----/g,
  // Raw JWT (no Bearer prefix): three base64url segments, starts "eyJ"
  // (base64 of the JSON header's leading `{"`).
  /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g,
]

export function normalizeCommand(text: string): string {
  return text
    .toLowerCase()
    .replace(/["'`\\]/g, "")
    .replace(/\$\{ifs\}/g, " ")
    .replace(/\$ifs\b/g, " ")
    .replace(/[;&|]+/g, " ")
    .replace(/\/bin\/rm\b/g, "rm")
    .replace(/\/usr\/bin\/rm\b/g, "rm")
    .replace(/\s+/g, " ")
    .trim()
}

export function redactSecrets(text: string): string {
  let out = text
  for (const re of SECRET_PATTERNS) {
    re.lastIndex = 0
    out = out.replace(re, "[REDACTED]")
  }
  // scheme://user:PASSWORD@host — redact only the password, keep the
  // rest (host/port/path) visible for debugging context. Scheme repetition
  // bounded to 20 (real schemes are a handful of chars) — round 11 finding:
  // an unbounded `*` here is O(n^2) on long input with no "://" anywhere,
  // since the engine retries a greedy-then-backtrack search from every
  // position (live-verified: 100k chars took 6.3s unbounded, 6ms bounded).
  out = out.replace(/([a-zA-Z][a-zA-Z0-9+.-]{0,20}:\/\/[^\s/:@]+):([^\s/@]{1,})@/g, "$1:[REDACTED]@")
  // Keyword may be embedded in a longer identifier (AWS_SECRET_ACCESS_KEY=...),
  // not just stand alone (password=...) — the keyword can appear anywhere
  // in the token, not only at its start.
  return out.replace(
    /(\b[a-z0-9_]*(?:api[_-]?key|password|passwd|secret|token)[a-z0-9_]*\s*[:=]\s*)([^\s"']{4,})/gi,
    "$1[REDACTED]",
  )
}

export function sha256Hex(text: string): string {
  return crypto.createHash("sha256").update(text, "utf8").digest("hex")
}

// Several CATASTROPHIC patterns use `.*`/`(\S*\s+)*` before a literal
// target (round 11 finding): on a long string with no real target, each
// occurrence of the pattern's trigger word forces its own O(remaining
// length) backtrack search, so a string with many trigger occurrences is
// O(n^2) overall — live-verified: ~1.6MB of "rm -rf junk..." froze the
// event loop for ~19s. Bounding the check to the same length Jev's own
// judgment already sees (rawDetail below truncates `joined` to this same
// 4000 chars) closes this without reducing real detection: nothing past
// this point is evaluated by either layer today.
const CATASTROPHIC_CHECK_MAX_CHARS = 4000

export function isCatastrophic(joined: string): boolean {
  const bounded = joined.length > CATASTROPHIC_CHECK_MAX_CHARS ? joined.slice(0, CATASTROPHIC_CHECK_MAX_CHARS) : joined
  const normalized = normalizeCommand(bounded)
  return CATASTROPHIC.some((re) => re.test(bounded) || re.test(normalized))
}

// Documented OpenCode permission keys (https://opencode.ai/docs/permissions/):
// read, edit, glob, grep, bash, task, skill, lsp, question, webfetch,
// websearch, external_directory, doom_loop. edit also covers write/apply_patch.
const READ_ACTIONS = new Set([
  "read",
  "glob",
  "grep",
  "external_directory",
  "lsp",
  "skill",
  "todowrite",
])
export function kindFor(action: string, resources: string[]): string {
  if (action === "question") return "multichoice"
  if (action === "doom_loop") return "destructive"
  if (READ_ACTIONS.has(action)) return "read"
  const text = resources.join("\n")
  if (DESTRUCTIVE_HINT.test(text)) return "destructive"
  return "write"
}

function numberedOptions(options: string[]): string {
  return options.map((o, i) => `${i + 1}. ${o}`).join("\n")
}

function resourceKinds(resources: string[]): string {
  return resources
    .map((r) => {
      const t = r.trim()
      if (!t) return "empty"
      if (t.startsWith("{") || t.startsWith("[")) {
        try {
          const p: unknown = JSON.parse(t)
          if (Array.isArray(p)) return `json-array[${p.length}]`
          if (p && typeof p === "object") return `json-keys:${Object.keys(p).slice(0, 8).join(",")}`
          return "json-scalar"
        } catch {
          return "json-broken"
        }
      }
      return `text:${t.length}ch`
    })
    .join("|")
}

function isEnabled(options: Record<string, unknown>): boolean {
  if (typeof options.enabled === "boolean") return options.enabled
  const env = (process.env.JEV_GATE_ENABLED ?? "").toLowerCase()
  if (env === "0" || env === "false" || env === "off" || env === "no") return false
  return true
}

function repoRoot(options: Record<string, unknown>): string {
  if (typeof options.gateDir === "string" && options.gateDir) return options.gateDir
  if (process.env.JEV_GATE_DIR) return process.env.JEV_GATE_DIR
  return path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..")
}

function apiKeyOf(options: Record<string, unknown>): string {
  if (typeof options.typesafeKey === "string" && options.typesafeKey) return options.typesafeKey
  return process.env.TYPESAFE_API_KEY ?? ""
}

function timeoutMsOf(options: Record<string, unknown>): number {
  const raw =
    (options.timeoutMs as unknown) ?? process.env.JEV_GATE_TIMEOUT_MS ?? process.env.JEV_GATE_TIMEOUT ?? 15000
  const n = typeof raw === "number" ? raw : parseInt(String(raw), 10)
  if (!Number.isFinite(n)) return 15000
  return Math.min(30000, Math.max(1000, n))
}

// How much recent conversation (chars, both roles) to send as OBJECTIVE.
// Default is generous (well past the old 500-char/user-only window) but
// still bounded: an unbounded full transcript would make every single
// permission check's cost and latency scale with session length.
// Override per-project via options.objectiveChars or JEV_GATE_OBJECTIVE_CHARS.
function objectiveBudgetOf(options: Record<string, unknown>): number {
  const raw = (options.objectiveChars as unknown) ?? process.env.JEV_GATE_OBJECTIVE_CHARS
  const n = typeof raw === "number" ? raw : parseInt(String(raw ?? ""), 10)
  if (!Number.isFinite(n)) return 4000
  return Math.min(20000, Math.max(200, n))
}

function logFileOf(options: Record<string, unknown>): string {
  if (typeof options.logFile === "string" && options.logFile) return options.logFile
  if (process.env.JEV_GATE_LOG) return process.env.JEV_GATE_LOG
  return path.join(repoRoot(options), "decisions-plugin.jsonl")
}

function logLine(options: Record<string, unknown>, entry: Record<string, unknown>): void {
  try {
    fs.appendFileSync(logFileOf(options), JSON.stringify({ v: 2, at: new Date().toISOString(), ...entry }) + "\n")
    try {
      fs.chmodSync(logFileOf(options), 0o600)
    } catch {
      // best effort
    }
  } catch {
    // Logging must never break the permission flow.
  }
}

// Cross-instance request claim: setup() may run more than once per
// process (and several processes may share a gateDir), so in-memory
// maps alone cannot guarantee a single evaluation/reply. First
// claimant wins via an exclusive marker file, claimed before the Jev
// call; losers skip evaluating entirely.
function repliedDirOf(options: Record<string, unknown>): string {
  return path.join(repoRoot(options), ".jev-gate-replied")
}

// Returns "won" (evaluate and reply now), "lost" (someone else owns
// it) or "error" (marker unusable — evaluate anyway, never suppress on
// FS trouble).
export function claimReply(options: Record<string, unknown>, requestID: string, inst: string): "won" | "lost" | "error" {
  // Length-bound the fast path too, not just the charset: an all-alnum
  // requestID over Linux's 255-byte NAME_MAX hits ENAMETOOLONG on the
  // write below, which used to land in the shared catch as generic
  // "error" for BOTH racing claimants — silently reopening the exact
  // double-evaluation race this function exists to close (round 8
  // review, live-verified: two calls for an identical 5000-char ID both
  // returned "error"). sha256Hex's fixed 64-char output is always safe.
  const name = /^[A-Za-z0-9_-]+$/.test(requestID) && requestID.length <= 200 ? requestID : sha256Hex(requestID)
  const dir = repliedDirOf(options)
  try {
    fs.mkdirSync(dir, { recursive: true })
  } catch {
    // The marker directory path itself is unusable (round 8 review,
    // live-verified: e.g. a plain file sitting where the directory
    // should be) — a broken marker mechanism, never a legitimate claim
    // conflict. Must not be reported as "lost" (which means "someone
    // else owns it" and, applied here, would permanently ask-human
    // every single permission/form forever, logged as the misleading
    // "duplicate-suppressed" — implying a race with a live second
    // instance, not a broken path — with no self-healing since
    // pruneReplied's own readdirSync on the same broken path also fails
    // silently). "error" correctly means "evaluate anyway" instead.
    return "error"
  }
  try {
    fs.writeFileSync(path.join(dir, name), inst, { flag: "wx" })
    return "won"
  } catch (err) {
    const code = (err as { code?: unknown }).code
    if (code === "EEXIST") return "lost"
    return "error"
  }
}

// The in-memory dedup collections (resolved/endedSessions/formSeen) have
// no eviction otherwise: confirmed by review that nothing ever calls
// .delete() on the success path, so a long-lived process accumulates one
// entry per ever-seen requestID/sessionID/formID for its whole uptime.
// A size cap, checked before each insert, is a simpler and lower-risk
// circuit breaker than retrofitting per-entry timestamps through every
// signature that touches these maps. Confirmed by a second review: no
// cross-request race (the event loop is sequential — see the ADR on that
// in docs/ARCHITECTURE.md — and inFlight itself is never capped), but
// clearing `resolved` early CAN drop the cached entry a late duplicate
// permission.asked would have used to retry a previously-failed reply
// (the issue #15 pattern) — that duplicate falls through to
// duplicate-suppressed instead of retrying. Not a lost or silently-wrong
// decision: alertHuman already fired synchronously when the original
// reply failed, so the operator was notified either way. At most one
// missed *automatic* self-heal on an already-rare, already-alerted path.
const MAX_DEDUP_ENTRIES = 2000

export function capped<T extends Map<string, unknown> | Set<string>>(collection: T, max: number = MAX_DEDUP_ENTRIES): T {
  if (collection.size >= max) collection.clear()
  return collection
}

function pruneReplied(options: Record<string, unknown>, maxAgeMs = 3600000): void {
  try {
    const dir = repliedDirOf(options)
    const now = Date.now()
    for (const f of fs.readdirSync(dir)) {
      try {
        const p = path.join(dir, f)
        if (now - fs.statSync(p).mtimeMs > maxAgeMs) fs.unlinkSync(p)
      } catch {
        // Keep going; pruning is best effort.
      }
    }
  } catch {
    // Directory may not exist yet; nothing to prune.
  }
}

/** Attention-grabbing desktop alert when Jev delegates to a human. */
export function alertHuman(title: string, body: string): void {
  const text = redactSecrets(body).slice(0, 400)
  const headline = title.slice(0, 120) || "Jev Decision Gate"
  try {
    const n = spawn(
      "notify-send",
      [
        "-u",
        "critical",
        "-t",
        "0",
        "-a",
        "Jev Decision Gate",
        "--hint=string:sound-name:dialog-warning",
        "--hint=string:desktop-entry:opencode",
        headline,
        text || "Jev needs your decision in OpenCode.",
      ],
      { stdio: "ignore", detached: true },
    )
    // spawn() reports a missing binary (ENOENT) asynchronously via an
    // 'error' event, not the synchronous throw the try/catch here
    // catches — an unhandled 'error' event is fatal to the whole process
    // (round 6 review, live-verified: on a host without notify-send,
    // the very first alertHuman() call — the escalation path for nearly
    // every fail-open/ask-human outcome — killed the entire opencode
    // host process, not just this notification). Every other spawn() in
    // this file already has this listener; these two were missed.
    n.on("error", () => {
      // Notification is best-effort.
    })
    n.unref?.()
  } catch {
    // Notification is best-effort.
  }
  try {
    const z = spawn(
      "zenity",
      ["--warning", "--title", headline, "--width=420", "--text", text || "Jev needs your decision in OpenCode."],
      { stdio: "ignore", detached: true },
    )
    z.on("error", () => {
      // Dialog is best-effort; notify-send alone is enough on headless.
    })
    z.unref?.()
  } catch {
    // Dialog is best-effort; notify-send alone is enough on headless.
  }
}

// Option labels come from the agent's own tool call (question fields), so
// they're attacker-reachable the same way OBJECTIVE/HALT.detail are —
// capped per-label (build_objective_block caps OBJECTIVE/detail too) and
// redacted before they become Jev's multichoice criteria (see
// build_questions in schemas.py). Not fenced like OBJECTIVE/detail: the
// pre-supplied "must be one of these options" check bounds what a
// resulting pick can do, so the goal here is capping cost/exposure, not
// closing a bypass — see SECURITY.md.
const LABEL_MAX_CHARS = 200

// Same normalization applied on both the way out (labelsFromFormField,
// what Jev sees) and the way back (valueForPick, matching Jev's pick to
// the original option): deterministic, so re-deriving it at lookup time
// stays correct even though filter/slice can shift indices, without
// needing a positional mapping between raw options and shown labels.
export function normalizedLabel(text: string): string {
  return redactSecrets(text).slice(0, LABEL_MAX_CHARS)
}

export function labelsFromFormField(field: unknown): string[] {
  if (!field || typeof field !== "object") return []
  const opts = (field as { options?: unknown }).options
  if (!Array.isArray(opts)) return []
  return opts
    .map((item) => {
      if (typeof item === "string") return item
      // A JSON array can legally hold null/undefined entries; valueForPick
      // already guards this (`item &&`) but this map didn't (4th
      // confirming-review round: crashed the whole form's auto-answer on
      // one bad entry instead of just skipping it).
      if (!item || typeof item !== "object") return null
      const o = item as { label?: unknown; value?: unknown }
      if (typeof o.label === "string" && o.label) return o.label
      if (typeof o.value === "string" && o.value) return o.value
      return null
    })
    .filter((label): label is string => typeof label === "string" && label.length > 0)
    .slice(0, 10)
    .map(normalizedLabel)
}

// Returns null when the pick is ambiguous: two different original options
// normalized (redacted/truncated) to the same string, so which one Jev
// "meant" can't be recovered — first-match-wins would silently apply a
// different, still-valid option than the one actually intended, with no
// signal anything went wrong (confirming-review finding). Callers must
// treat null the same as "pick not offered": ask-human, don't guess.
export function valueForPick(field: unknown, pick: string): string | null {
  if (!field || typeof field !== "object") return pick
  const opts = (field as { options?: unknown }).options
  if (!Array.isArray(opts)) return pick
  const matches: string[] = []
  for (const item of opts) {
    if (typeof item === "string") {
      if (normalizedLabel(item) === pick) matches.push(item)
      continue
    }
    if (item && typeof item === "object") {
      const o = item as { label?: unknown; value?: unknown }
      const rawLabel = typeof o.label === "string" && o.label ? o.label : typeof o.value === "string" && o.value ? o.value : null
      if (rawLabel !== null && normalizedLabel(rawLabel) === pick) {
        matches.push(typeof o.value === "string" && o.value ? o.value : pick)
      }
    }
  }
  const distinct = new Set(matches)
  if (distinct.size > 1) return null
  return matches.length > 0 ? matches[0] : pick
}

/** List pending interactive forms (question tool uses kind=question forms on 2.0.x). */
export function listPendingForms(): Promise<Array<Record<string, unknown>>> {
  return new Promise((resolve) => {
    const child = spawn("opencode", ["api", "GET", "/api/form"], {
      env: process.env,
      stdio: ["ignore", "pipe", "pipe"],
    })
    let stdout = ""
    const timer = setTimeout(() => {
      try {
        child.kill("SIGTERM")
      } catch {
        // ignore
      }
      // Same SIGKILL backstop spawnGate's timeout/cancel paths already have
      // (round 13 review) — this call site was left out of that fix (round
      // 14 review, live-verified: a hung `opencode` CLI that ignores
      // SIGTERM stays alive indefinitely, and this runs on every 750ms
      // poll tick with no backpressure, so a single hang leaks one
      // orphaned process per tick).
      const killer = setTimeout(() => {
        try {
          child.kill("SIGKILL")
        } catch {
          // ignore
        }
      }, 2000)
      killer.unref?.()
      resolve([])
    }, 5000)
    child.stdout?.on("data", (c) => {
      if (stdout.length < 256_000) stdout += String(c)
    })
    child.on("error", () => {
      clearTimeout(timer)
      resolve([])
    })
    child.on("close", () => {
      clearTimeout(timer)
      try {
        const parsed = JSON.parse(stdout) as { data?: unknown } | unknown
        const data = parsed && typeof parsed === "object" && Array.isArray((parsed as { data?: unknown }).data)
          ? (parsed as { data: unknown[] }).data
          : Array.isArray(parsed)
            ? parsed
            : []
        resolve(data.filter((x): x is Record<string, unknown> => !!x && typeof x === "object") as Record<string, unknown>[])
      } catch {
        resolve([])
      }
    })
  })
}

/** POST a reply to an OpenCode API endpoint via the CLI (`opencode api POST`), never
 * `ctx.permission.reply()`. Root cause of issue #15: live testing found a permission
 * the SDK method reported "Permission request not found" for was STILL listed as
 * pending via GET /api/session/{id}/permission minutes later, and a raw
 * `opencode api POST .../reply` on that exact requestID succeeded immediately — this
 * was never a server-side expiry/TTL race, the SDK method itself is what's unreliable
 * here (plausibly related to setup() running more than once per process — see
 * claimReply). Shared by replyFormAnswer and replyPermission below. */
export function postApiReply(apiPath: string, body: Record<string, unknown>, errPrefix: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const child = spawn("opencode", ["api", "POST", apiPath, "-d", JSON.stringify(body)], {
      env: process.env,
      stdio: ["ignore", "pipe", "pipe"],
    })
    let stderr = ""
    const timer = setTimeout(() => {
      try {
        child.kill("SIGTERM")
      } catch {
        // ignore
      }
      // Same SIGKILL backstop spawnGate's timeout/cancel paths already have
      // (round 13 review) — this call site was left out of that fix
      // (round 14 review, live-verified). Every permission/form reply goes
      // through here.
      const killer = setTimeout(() => {
        try {
          child.kill("SIGKILL")
        } catch {
          // ignore
        }
      }, 2000)
      killer.unref?.()
      reject(new Error(`${errPrefix} timeout`))
    }, 10000)
    child.stderr?.on("data", (c) => {
      if (stderr.length < 4000) stderr += String(c)
    })
    child.on("error", (err) => {
      clearTimeout(timer)
      reject(err)
    })
    child.on("close", (code) => {
      clearTimeout(timer)
      if (code === 0) resolve()
      else reject(new Error(`${errPrefix} exit ${code}: ${stderr.slice(0, 200)}`))
    })
  })
}

/** Submit answers to a pending OpenCode form (question tool on 2.0.x). */
function replyFormAnswer(sessionID: string, formID: string, answer: Record<string, string>): Promise<void> {
  return postApiReply(`/api/session/${sessionID}/form/${formID}/reply`, { answer }, "form-reply")
}

function replyPermission(sessionID: string, requestID: string, decision: "once" | "reject"): Promise<void> {
  return postApiReply(`/api/session/${sessionID}/permission/${requestID}/reply`, { decision }, "permission-reply")
}

function pythonBin(options: Record<string, unknown>): string {
  if (typeof options.pythonBin === "string" && options.pythonBin) return options.pythonBin
  if (process.env.JEV_GATE_PYTHON) return process.env.JEV_GATE_PYTHON
  // The opencode service often runs with /usr/bin/python3, which may not
  // have typesafe-sdk. Prefer a mise-managed interpreter when present.
  const home = process.env.HOME || ""
  const miseRoot = path.join(home, ".local/share/mise/installs/python")
  try {
    const versions = fs.readdirSync(miseRoot).sort().reverse()
    for (const v of versions) {
      const bin = path.join(miseRoot, v, "bin", "python3")
      if (fs.existsSync(bin)) return bin
    }
  } catch {
    // fall through
  }
  return "python3"
}

function minimalEnv(options: Record<string, unknown>): Record<string, string | undefined> {
  const root = repoRoot(options)
  const src = path.join(root, "src")
  const existing = process.env.PYTHONPATH ?? ""
  const pyPath = existing ? `${src}${path.delimiter}${existing}` : src
  return {
    PATH: process.env.PATH,
    HOME: process.env.HOME,
    PYTHONPATH: pyPath,
    TYPESAFE_API_KEY: apiKeyOf(options),
    JEV_GATE_LOG: logFileOf(options),
    JEV_GATE_CLI_LOG: "0",
    JEV_MODEL: process.env.JEV_MODEL,
    JEV_GATE_DIR: process.env.JEV_GATE_DIR ?? root,
    SSL_CERT_FILE: process.env.SSL_CERT_FILE,
    REQUESTS_CA_BUNDLE: process.env.REQUESTS_CA_BUNDLE,
    HTTPS_PROXY: process.env.HTTPS_PROXY,
    HTTP_PROXY: process.env.HTTP_PROXY,
    NO_PROXY: process.env.NO_PROXY,
  }
}

// Spawns the gate subprocess without writing stdin yet, so its cold start
// (interpreter init, `typesafe_sdk` import) can overlap with an async
// caller-side step (objectiveFor's session.context RPC) instead of paying
// both costs back to back. Every permission.reply() this plugin makes
// races a short, non-configurable server-side window (see
// docs/TROUBLESHOOTING.md "Ordinary permission replies can silently miss
// the window", issue #15) — this does not close that race, it narrows it.
function spawnGate(options: Record<string, unknown>): {
  send: (event: Record<string, unknown>) => void
  cancel: () => void
  result: Promise<Record<string, unknown>>
} {
  const child = spawn(pythonBin(options), ["-m", "jev_gate.cli"], {
    cwd: repoRoot(options),
    env: minimalEnv(options),
  })
  let stdout = ""
  let stderr = ""
  const CAP = 256 * 1024
  let settleResolve!: (value: Record<string, unknown>) => void
  let settleReject!: (reason: unknown) => void
  const result = new Promise<Record<string, unknown>>((resolve, reject) => {
    settleResolve = resolve
    settleReject = reject
  })
  const timer = setTimeout(() => {
    try {
      child.kill("SIGTERM")
    } catch {
      // ignore
    }
    const killer = setTimeout(() => {
      try {
        child.kill("SIGKILL")
      } catch {
        // ignore
      }
    }, 2000)
    killer.unref?.()
    settleReject(new Error("gate timeout"))
  }, timeoutMsOf(options))
  ;(timer as unknown as { unref?: () => void }).unref?.()
  child.stdout.on("data", (chunk) => {
    if (stdout.length < CAP) stdout += String(chunk).slice(0, CAP - stdout.length)
  })
  child.stderr.on("data", (chunk) => {
    if (stderr.length < CAP) stderr += String(chunk).slice(0, CAP - stderr.length)
  })
  child.on("error", (error) => {
    clearTimeout(timer)
    settleReject(error)
  })
  child.on("close", (code) => {
    clearTimeout(timer)
    if (code !== 0) {
      settleReject(new Error("gate exit " + String(code) + " " + stderr.slice(0, 200)))
      return
    }
    try {
      settleResolve(JSON.parse(stdout) as Record<string, unknown>)
    } catch (parseError) {
      settleReject(parseError)
    }
  })
  return {
    send(event) {
      try {
        child.stdin.write(JSON.stringify(event))
        child.stdin.end()
      } catch (stdinError) {
        clearTimeout(timer)
        settleReject(stdinError)
      }
    },
    cancel() {
      clearTimeout(timer)
      try {
        child.kill("SIGTERM")
      } catch {
        // ignore
      }
      // Same SIGKILL backstop as the timeout path above: without it, a
      // child that doesn't die on SIGTERM (installed its own handler, or
      // just misses the signal) leaks forever — cancel() has no other
      // caller to retry it (round 13 review, live-verified: a child that
      // ignores SIGTERM stayed alive at least 8s past cancel() with no
      // fix, with nothing left anywhere to clean it up).
      const killer = setTimeout(() => {
        try {
          child.kill("SIGKILL")
        } catch {
          // ignore
        }
      }, 2000)
      killer.unref?.()
      // Swallow the eventual close/error event so it doesn't surface as an
      // unhandled rejection once nothing is awaiting `result` anymore.
      result.catch(() => {})
    },
    result,
  }
}

function runGate(options: Record<string, unknown>, event: Record<string, unknown>): Promise<Record<string, unknown>> {
  const gate = spawnGate(options)
  gate.send(event)
  return gate.result
}

type ConversationTurn = { role: "user" | "assistant"; text: string }

export function textOfMessage(message: unknown): ConversationTurn | null {
  if (!message || typeof message !== "object") return null
  const msg = message as { type?: unknown; role?: unknown; text?: unknown; parts?: unknown; content?: unknown }
  // v2 shape: { type: "user"|"assistant", text: "..." }. Legacy shape:
  // { role: "user"|"assistant", parts: [{ text }] }.
  const role = msg.type === "user" || msg.role === "user"
    ? "user"
    : msg.type === "assistant" || msg.role === "assistant"
      ? "assistant"
      : null
  if (role === null) return null
  if (typeof msg.text === "string" && msg.text.trim()) return { role, text: msg.text }
  // Real assistant-message shape (round 15 review, confirmed against the
  // installed @opencode/client types, not just observed behavior):
  // SessionMessageAssistant has neither .text nor .parts at all — its text
  // lives in content[].text for "text"/"reasoning" items ("tool" items
  // have no plain text and are skipped, same reasoning as the .parts
  // branch below). Without this, every assistant turn silently vanished
  // from what Jev is shown, despite the surrounding code's own comment
  // that OBJECTIVE should reflect "what the agent has been doing, not
  // just the human's last message."
  if (Array.isArray(msg.content)) {
    const text = msg.content
      .filter((p): p is { type?: unknown; text?: unknown } => !!p && typeof p === "object")
      .filter((p) => (p.type === "text" || p.type === "reasoning") && typeof p.text === "string")
      .map((p) => p.text as string)
      .join("\n")
    if (text.trim()) return { role, text }
  }
  if (Array.isArray(msg.parts)) {
    // Only plain text parts (thinking/response). Tool-call parts have no
    // `.text` field and are skipped, keeping this cheap even for turns
    // with large tool output.
    const text = msg.parts
      .filter((p): p is { text?: unknown } => !!p && typeof p === "object")
      .filter((p) => typeof p.text === "string")
      .map((p) => p.text as string)
      .join("\n")
    if (text.trim()) return { role, text }
  }
  return null
}

class SessionEndedError extends Error {
  constructor(message = "session-ended") {
    super(message)
    this.name = "SessionEndedError"
  }
}

function archivedAt(info: unknown): unknown {
  if (!info || typeof info !== "object") return undefined
  const time = (info as { time?: unknown }).time
  if (!time || typeof time !== "object") return undefined
  return (time as { archived?: unknown }).archived
}

// The opencode SDK's error surface for "this session is gone" overlaps in
// wording with a dozen unrelated *NotFoundError types (ProviderNotFoundError,
// AgentNotFoundError, SkillNotFoundError, McpServerNotFoundError,
// CommandNotFoundError, FileNotFoundError, ...) — confirmed reachable: a
// bare /not found/i (as this used to be) matches "Provider anthropic not
// found" just as readily as an actual session error. Misclassifying one of
// those as "session ended" is worse than it sounds: the session gets
// permanently cached as ended (5th confirming-review round found this is
// the ONE fail path in the file with no alertHuman — every other error
// path degrades to ask-human with an alert; this one just silently stops
// replying for that session, forever, violating SECURITY.md's "never
// silently allows" guarantee in spirit even though it denies rather than
// allows). Checking the SDK's own `_tag` first (Effect's TaggedStruct
// discriminant — SessionNotFoundError is the real one) is precise when
// present; the regex fallback now requires "session" to co-occur with the
// not-found-ish wording instead of either alone, closing the cross-
// contamination with sibling *NotFoundError types. Deliberately not adding
// alertHuman here too: fixing the false-positive source is the real fix,
// and a genuinely-ended session has nothing left for a human to act on —
// alerting on every correct classification would just be noise for the
// common case this was actually built to handle.
export function looksLikeSessionGone(err: unknown): boolean {
  const tag = (err as { _tag?: unknown } | null | undefined)?._tag
  if (tag === "SessionNotFoundError") return true
  const msg = err instanceof Error ? err.message : String(err)
  return /\bsession\b/i.test(msg) && /not\s*found|unknown|no such|deleted|archived/i.test(msg)
}

async function sessionIsEnded(
  ctx: { session: { get?: (input: { sessionID: string }) => Promise<unknown>; context: (input: { sessionID: string }) => Promise<unknown> } },
  sessionID: string,
  ended: Set<string>,
): Promise<boolean> {
  if (ended.has(sessionID)) return true
  if (typeof ctx.session.get !== "function") return false
  try {
    const info = await ctx.session.get({ sessionID })
    if (archivedAt(info) != null) {
      capped(ended).add(sessionID)
      return true
    }
    return false
  } catch (err) {
    if (looksLikeSessionGone(err)) {
      capped(ended).add(sessionID)
      return true
    }
    return false
  }
}

async function objectiveFor(
  ctx: { session: { context: (input: { sessionID: string }) => Promise<unknown> } },
  sessionID: string,
  ended: Set<string>,
  budgetChars: number,
): Promise<string> {
  try {
    const messages = await ctx.session.context({ sessionID })
    const list = Array.isArray(messages) ? messages : []
    const turns = list.map(textOfMessage).filter((t): t is ConversationTurn => t !== null)
    // Recent conversation, both roles, newest last: lets Jev judge
    // whether a halt matches what the human asked AND what the agent
    // has been doing, not just the human's last message. Walk backward
    // so a budget cut drops the oldest turns first; each turn is also
    // capped so one huge message can't eat the whole budget.
    const lines: string[] = []
    let total = 0
    for (let i = turns.length - 1; i >= 0 && total < budgetChars; i--) {
      const line = `${turns[i].role === "user" ? "User" : "Assistant"}: ${turns[i].text}`.slice(0, 1000)
      lines.unshift(line)
      total += line.length + 1
    }
    const transcript = redactSecrets(lines.join("\n")).slice(-budgetChars)
    return transcript || "Complete the assigned coding task"
  } catch (err) {
    if (looksLikeSessionGone(err)) {
      capped(ended).add(sessionID)
      const msg = err instanceof Error ? err.message : String(err)
      throw new SessionEndedError(msg.slice(0, 120))
    }
    return "Complete the assigned coding task"
  }
}

export default Plugin.define({
  id: "jev-decision-gate",
  async setup(ctx) {
    const options = ((ctx as { options?: unknown }).options ?? {}) as Record<string, unknown>
    if (!isEnabled(options)) return
    // Dedupe: the server may emit the same permission request more than
    // once while it is pending. Evaluate once per requestID; concurrent
    // duplicates await the same promise, late duplicates reuse the cached
    // reply without calling Jev again.
    const inFlight = new Map<string, Promise<Record<string, unknown>>>()
    const resolved = new Map<string, { decision: string; repliedOk: boolean }>()
    const endedSessions = new Set<string>()
    const inst = Math.random().toString(36).slice(2, 8)
    const logEv = (entry: Record<string, unknown>): void =>
      logLine(options, { inst, pid: process.pid, ...entry })
    pruneReplied(options)
    // pruneReplied only ran once, at setup() — a long-running opencode host
    // process (days/weeks, setup() never re-invoked) accumulates one marker
    // file per permission/form forever (round 12 finding, live-verified:
    // 5000 claimReply calls -> 5000 unpruned files). Same class of bug
    // already fixed for the in-memory collections via capped(); this is
    // its on-disk sibling. Cadence matches pruneReplied's own maxAgeMs
    // default (1h) — no need to poll as often as the form-list.
    const pruneTimer = setInterval(() => pruneReplied(options), 3600000)
    ;(pruneTimer as unknown as { unref?: () => void }).unref?.()
    const controller = new AbortController()
    const formSeen = new Set<string>()
    // Poll pending forms: on opencode 2.0.x the question tool opens a
    // form (metadata.kind=question). Event names vary; polling /api/form
    // is the durable autonomy path.
    const pollMs = 750
    const pollTimer = setInterval(() => {
      void (async () => {
        const pending = await listPendingForms()
        for (const item of pending) {
          const id = String(item.id ?? "")
          if (!id || formSeen.has(id)) continue
          // Answer question-kind forms; other forms also get Jev if they have options.
          capped(formSeen).add(id)
          try {
            await handleFormAsked(ctx as Parameters<typeof handleFormAsked>[0], logEv, inst, options, item, endedSessions)
          } catch {
            formSeen.delete(id)
          }
        }
      })()
    }, pollMs)
    ;(pollTimer as unknown as { unref?: () => void }).unref?.()
    void (async () => {
      try {
        for await (const event of ctx.event.subscribe({ signal: controller.signal })) {
        const evt = event as { type?: string; data?: Record<string, unknown>; properties?: Record<string, unknown> }
        if (evt.type === "session.deleted") {
          const dead = String((evt.data ?? evt.properties ?? {}).sessionID ?? "")
          if (dead) capped(endedSessions).add(dead)
          continue
        }
        // Forms (question tool on 2.0.x) and legacy question events.
        if (
          evt.type === "form.created" ||
          evt.type === "question.v2.asked" ||
          evt.type === "question.asked"
        ) {
          const payload = (evt.properties ?? evt.data ?? {}) as Record<string, unknown>
          const form = (payload.form && typeof payload.form === "object"
            ? (payload.form as Record<string, unknown>)
            : payload) as Record<string, unknown>
          const fid = String(form.id ?? payload.id ?? "")
          if (fid) capped(formSeen).add(fid)
          // handleFormAsked re-derives its own formID from *this* payload's
          // .id alone (no further fallback) — if the real id only lived at
          // the outer event's payload.id (form.id itself absent), fid above
          // resolves it correctly but handleFormAsked would still see
          // formID="" and hit its missing-ids early return, permanently
          // stuck: nothing gets claimed on disk (claimReply never runs),
          // yet formSeen is now marked forever, blocking the poll path's
          // retry for a form nothing ever actually processed (round 14
          // review). Hand it a form object whose .id already matches fid.
          const formForHandler = fid && !form.id ? { ...form, id: fid } : form
          const task = handleFormAsked(ctx, logEv, inst, options, formForHandler, endedSessions)
          void task.catch(() => {
            // Failures are logged inside the handler. Mirror the poll
            // path's own cleanup (round 14 review): most failures inside
            // handleFormAsked are swallowed by its own internal fail-open
            // catch and never reject here, but a throw BEFORE its
            // claimReply call (e.g. missing-ids on a malformed event) never
            // claims anything on disk — leaving fid in formSeen forever
            // would permanently block the poll path's own retry for a form
            // that was never actually claimed.
            if (fid) formSeen.delete(fid)
          })
          continue
        }
        if (evt.type !== "permission.asked") continue
        const data = evt.data ?? evt.properties ?? {}
        const sessionID = String(data.sessionID ?? "")
        const requestID = String(data.id ?? "")
        const action = String((data as { action?: unknown }).action ?? "")
        const resources = Array.isArray((data as { resources?: unknown }).resources)
          ? ((data as { resources: unknown[] }).resources.map(String))
          : []
        if (!sessionID || !requestID) {
          logEv({
            sessionID: sessionID || null,
            requestID: requestID || null,
            tool: action || null,
            gateAction: "ask-human",
            reason: "missing-ids",
          })
          continue
        }
        if (await sessionIsEnded(ctx as Parameters<typeof sessionIsEnded>[0], sessionID, endedSessions)) {
          logEv({
            sessionID,
            requestID,
            tool: action,
            gateAction: "ask-human",
            reason: "session-ended",
          })
          continue
        }

        const cached = resolved.get(requestID)
        if (cached) {
          if (!cached.repliedOk && cached.decision !== "ask-human") {
            try {
              await replyPermission(sessionID, requestID, cached.decision === "allow" ? "once" : "reject")
              cached.repliedOk = true
            } catch {
              // Still pending or already resolved; nothing more to do.
            }
          } else {
            logEv({ sessionID, requestID, tool: action, gateAction: cached.decision === "allow" ? "allow" : cached.decision === "deny" ? "deny" : "ask-human", reason: "duplicate-suppressed" })
          }
          continue
        }
        const ongoing = inFlight.get(requestID)
        if (ongoing) {
          try {
            await ongoing
          } catch {
            // First evaluation owns the outcome; duplicates just wait.
          }
          continue
        }

        const task = handleOne(ctx, logEv, inst, options, sessionID, requestID, action, resources, endedSessions)
        inFlight.set(requestID, task)
        try {
          const outcome = await task
          capped(resolved).set(requestID, outcome)
        } catch {
          capped(resolved).set(requestID, { decision: "ask-human", repliedOk: true })
        } finally {
          inFlight.delete(requestID)
        }
      }
      } catch {
        // Subscription ended (server shutdown). Nothing to report.
      }
    })()
    return () => {
      clearInterval(pollTimer)
      clearInterval(pruneTimer)
      controller.abort()
    }
  },
})

async function handleFormAsked(
  ctx: { session: { get?: (input: { sessionID: string }) => Promise<unknown>; context: (input: { sessionID: string }) => Promise<unknown> } },
  log: (entry: Record<string, unknown>) => void,
  inst: string,
  options: Record<string, unknown>,
  payload: Record<string, unknown>,
  endedSessions: Set<string>,
): Promise<void> {
  const sessionID = String(payload.sessionID ?? "")
  const formID = String(payload.id ?? "")
  if (!sessionID || !formID) {
    log({ sessionID: sessionID || null, requestID: formID || null, tool: "question", gateAction: "ask-human", reason: "missing-ids" })
    return
  }
  const claim = claimReply(options, `form:${formID}`, inst)
  if (claim === "lost") {
    log({ sessionID, requestID: formID, tool: "question", gateAction: "ask-human", reason: "duplicate-suppressed" })
    return
  }
  if (await sessionIsEnded(ctx, sessionID, endedSessions)) {
    log({ sessionID, requestID: formID, tool: "question", gateAction: "ask-human", reason: "session-ended" })
    return
  }

  const fields = Array.isArray(payload.fields) ? payload.fields : []
  const answer: Record<string, string> = {}
  const picks: string[] = []

  try {
    let objective = "Answer the agent's multiple-choice question to unblock the session"
    try {
      objective = await objectiveFor(ctx, sessionID, endedSessions, Math.min(1500, objectiveBudgetOf(options)))
    } catch {
      // keep fallback
    }

    for (let fi = 0; fi < Math.max(fields.length, 1); fi++) {
      const field = fields[fi]
      const key =
        field && typeof field === "object" && typeof (field as { key?: unknown }).key === "string"
          ? String((field as { key: string }).key)
          : `q${fi}`
      const labels = labelsFromFormField(field)
      const title = field && typeof field === "object" ? String((field as { title?: unknown }).title ?? "") : ""
      const description =
        field && typeof field === "object" ? String((field as { description?: unknown }).description ?? "") : ""
      const detail = redactSecrets(
        [title, description, labels.map((l, i) => `${i + 1}. ${l}`).join("\n")].filter(Boolean).join("\n").slice(0, 4000),
      )
      const halt: Record<string, unknown> = {
        kind: "multichoice",
        tool: "question",
        detail: detail || "agent question form",
      }
      if (labels.length > 0) {
        halt.options = labels
        halt.numbered = numberedOptions(labels)
      }
      const startedAt = Date.now()
      const decision = await runGate(options, {
        objective,
        halt,
        context: { sessionID, requestID: formID, risk_hints: "interactive-form-question", fieldIndex: fi },
        policy: { default: "ask-human when unsure" },
      })
      const elapsedMs = Date.now() - startedAt
      log({
        sessionID,
        requestID: formID,
        tool: "question",
        kind: "multichoice",
        gateAction: decision.action,
        reason: decision.reason,
        confidence: decision.confidence,
        model: decision.model,
        pick: decision.pick ?? null,
        elapsedMs,
        objectiveChars: objective.length,
        hasKey: apiKeyOf(options) !== "",
        optionsCount: labels.length,
        fieldKey: key,
        ...(typeof decision.error === "string" ? { error_class: decision.error } : {}),
        phase: "form-answer",
      })

      if (decision.action !== "allow" || typeof decision.pick !== "string" || !decision.pick) {
        alertHuman(
          "Jev necesita tu decisión",
          `Formulario: ${description || title || detail}`.slice(0, 280),
        )
        return
      }
      if (labels.length > 0 && !labels.includes(decision.pick)) {
        alertHuman("Jev: opción inválida", `Jev eligió "${decision.pick}" fuera de la lista. Responde en OpenCode.`)
        return
      }
      const value = valueForPick(field, decision.pick)
      if (value === null) {
        alertHuman(
          "Jev: opción ambigua",
          `Dos opciones distintas se ven igual tras redactar/truncar ("${decision.pick}"). Responde en OpenCode.`,
        )
        return
      }
      picks.push(decision.pick)
      answer[key] = value
    }

    try {
      await replyFormAnswer(sessionID, formID, answer)
      log({
        sessionID,
        requestID: formID,
        tool: "question",
        gateAction: "allow",
        reason: "question-answered",
        pick: picks.join(" | "),
      })
    } catch (err) {
      log({
        sessionID,
        requestID: formID,
        tool: "question",
        gateAction: "ask-human",
        reason: "form-reply-failed",
        error_class: err instanceof Error ? err.message.slice(0, 120) : "exception",
      })
      alertHuman("Jev no pudo responder", `Fallo al enviar la respuesta del formulario. ${String(err).slice(0, 160)}`)
    }
  } catch (err) {
    log({
      sessionID,
      requestID: formID,
      tool: "question",
      kind: "multichoice",
      gateAction: "ask-human",
      reason: "fail-open",
      error_class: err instanceof Error ? err.message.slice(0, 120) : "exception",
      phase: "form-answer",
    })
    alertHuman("Jev necesita tu decisión", "Error evaluando el formulario del agente. Responde en OpenCode.")
  }
}

export async function handleOne(
  ctx: { session: { get?: (input: { sessionID: string }) => Promise<unknown>; context: (input: { sessionID: string }) => Promise<unknown> } },
  log: (entry: Record<string, unknown>) => void,
  inst: string,
  options: Record<string, unknown>,
  sessionID: string,
  requestID: string,
  action: string,
  resources: string[],
  endedSessions: Set<string>,
): Promise<{ decision: string; repliedOk: boolean }> {
  // From permission.asked to whenever we attempt (or give up on) a reply —
  // used to diagnose the reply-vs-server-window race (issue #15), not just
  // Jev's own call time (which runGate already measures separately).
  const receivedAt = Date.now()
  // Claim the whole request (evaluation + reply) before calling Jev, not
  // just before replying. setup() runs more than once per opencode
  // process (confirmed in production logs: same pid, different inst),
  // so without this, every instance independently evaluates and races
  // to reply to the same permission — 2-3x Jev calls and, for the
  // interactive question tool, a reply race against the human's own
  // answer. First claimant wins via an exclusive marker file; losers
  // never touch Jev at all.
  const claim = claimReply(options, requestID, inst)
  if (claim === "lost") {
    log({ sessionID, requestID, tool: action, gateAction: "ask-human", reason: "duplicate-suppressed" })
    return { decision: "ask-human", repliedOk: true }
  }

  const joined = resources.join("\n")
  const resKinds = resourceKinds(resources)
  if (isCatastrophic(joined)) {
    log({ sessionID, requestID, tool: action, kind: "destructive", gateAction: "reject", reason: "catastrophic-pattern", detail_sha256: sha256Hex(joined) })
    let repliedOk = true
    try {
      await replyPermission(sessionID, requestID, "reject")
    } catch (err) {
      log({ sessionID, requestID, tool: action, gateAction: "reject", reason: "reply-failed", error_class: err instanceof Error ? err.message.slice(0, 120) : "exception", totalElapsedMs: Date.now() - receivedAt })
      repliedOk = false
      // The reject was computed but never delivered — the tool call may be
      // hanging with no signal at all otherwise. See docs/TROUBLESHOOTING.md
      // "Ordinary permission replies can silently miss the window".
      alertHuman("Jev: bloqueo no entregado a tiempo", `${action}: patrón catastrófico detectado, pero la respuesta llegó tarde. Revisa OpenCode.`)
    }
    return { decision: "deny", repliedOk }
  }

  // question permission: allow the tool without session.context / Jev.
  // Answering happens by polling /api/form and POSTing form replies.
  // Touching session.context here was implicated in the post-pick hang.
  if (action === "question") {
    let repliedOk = true
    try {
      await replyPermission(sessionID, requestID, "once")
    } catch (err) {
      log({
        sessionID,
        requestID,
        tool: action,
        kind: "multichoice",
        gateAction: "allow",
        reason: "reply-failed",
        error_class: err instanceof Error ? err.message.slice(0, 120) : "exception",
        totalElapsedMs: Date.now() - receivedAt,
      })
      repliedOk = false
      alertHuman("Jev: pregunta no desbloqueada a tiempo", "La herramienta de pregunta puede haberse quedado colgada. Revisa OpenCode.")
    }
    log({
      sessionID,
      requestID,
      tool: action,
      kind: "multichoice",
      gateAction: "allow",
      reason: "question-permission-passthrough",
      detail_sha256: sha256Hex(joined),
      resKinds,
      repliedOk,
    })
    return { decision: "allow", repliedOk }
  }

  const kind = kindFor(action, resources)

  // spawnGate is called INSIDE the try (round 10 review, live-verified):
  // spawn() throws SYNCHRONOUSLY, not via a rejected promise, when an env
  // value derived from options (e.g. a NUL byte in a malformed
  // typesafeKey/logFile/gateDir) is invalid. Outside the try, that throw
  // propagated out of handleOne entirely, past every log()/alertHuman()
  // call in this function, caught only by setup()'s bare event-loop catch
  // — which logs nothing, alerts no one, and marks repliedOk:true so a
  // later duplicate permission.asked for the same requestID never even
  // retries (claimReply already claimed it). Strictly worse than every
  // other fail-open path in this file, which was built specifically to
  // never fail silently.
  try {
    // Spawn the gate subprocess before objectiveFor's session.context RPC
    // resolves, not after: its cold start (interpreter init, typesafe_sdk
    // import) then overlaps with that RPC instead of adding to it serially.
    // Every millisecond here is one this permission's reply doesn't get to
    // spend against the server's reply window (issue #15).
    const gate = spawnGate(options)
    const startedAt = Date.now()
    let objective: string
    try {
      objective = await objectiveFor(ctx, sessionID, endedSessions, objectiveBudgetOf(options))
    } catch (err) {
      gate.cancel()
      throw err
    }
    const rawDetail = joined.slice(0, 4000)
    const detail = redactSecrets(rawDetail)
    const hintParts: string[] = []
    if (action === "doom_loop") hintParts.push("doom_loop: identical tool call repeated")
    if (DESTRUCTIVE_HINT.test(joined)) hintParts.push("matches destructive-hint")
    if (COMMAND_SUBSTITUTION.test(joined)) hintParts.push("contains command substitution ($(...) or `...`) — real effect cannot be statically determined")
    const riskHints = hintParts.join("; ")
    const halt: Record<string, unknown> = { kind, tool: action, detail }
    const gateEvent = {
      objective,
      halt,
      context: { sessionID, requestID, risk_hints: riskHints },
      policy: { default: "ask-human when unsure" },
    }
    gate.send(gateEvent)
    const decision = await gate.result
    // Spans spawn → decision (overlaps objectiveFor's RPC), not just the
    // subprocess's own runtime — larger than pre-issue-#15-fix elapsedMs
    // values for the same underlying Jev call; that's the full budget that
    // matters for the reply-window race, not a regression.
    const elapsedMs = Date.now() - startedAt
    log({
      sessionID,
      requestID,
      tool: action,
      kind,
      gateAction: decision.action,
      reason: decision.reason,
      confidence: decision.confidence,
      model: decision.model,
      pick: decision.pick ?? null,
      elapsedMs,
      objectiveChars: objective.length,
      detail_sha256: sha256Hex(joined),
      hasKey: apiKeyOf(options) !== "",
      resKinds,
      ...(typeof decision.error === "string" ? { error_class: decision.error } : {}),
    })
    let repliedOk = true
    if (decision.action === "allow" || decision.action === "deny") {
      try {
        await replyPermission(sessionID, requestID, decision.action === "allow" ? "once" : "reject")
      } catch (err) {
        log({
          sessionID,
          requestID,
          tool: action,
          gateAction: decision.action,
          reason: "reply-failed",
          error_class: err instanceof Error ? err.message.slice(0, 120) : "exception",
          totalElapsedMs: Date.now() - receivedAt,
        })
        repliedOk = false
        // Jev decided, but the reply arrived after the server stopped
        // tracking the request — the tool call is likely hanging with no
        // other signal. See docs/TROUBLESHOOTING.md "Ordinary permission
        // replies can silently miss the window" (issue #15).
        alertHuman(
          "Jev: decisión no entregada a tiempo",
          `${action} → ${decision.action}, pero la respuesta llegó tarde. La tool call puede haberse quedado colgada; revisa OpenCode.`,
        )
      }
    } else {
      alertHuman(
        "Jev necesita tu decisión",
        `${action}: ${detail.slice(0, 220) || "permiso pendiente en OpenCode"}`,
      )
    }
    return { decision: String(decision.action), repliedOk }
  } catch (err) {
    if (err instanceof SessionEndedError || endedSessions.has(sessionID)) {
      log({
        sessionID,
        requestID,
        tool: action,
        kind,
        gateAction: "ask-human",
        reason: "session-ended",
        error_class: err instanceof Error ? err.message.slice(0, 120) : "exception",
      })
      return { decision: "ask-human", repliedOk: true }
    }
    log({
      sessionID,
      requestID,
      tool: action,
      kind,
      gateAction: "ask-human",
      reason: "fail-open",
      error_class: err instanceof Error ? err.message.slice(0, 120) : "exception",
    })
    alertHuman("Jev: error del gate", `Fail-open. Revisa OpenCode (${action}).`)
    return { decision: "ask-human", repliedOk: true }
  }
}
