import { Plugin } from "@opencode/plugin"
import { spawn } from "node:child_process"
import crypto from "node:crypto"
import fs from "node:fs"
import path from "node:path"
import { fileURLToPath } from "node:url"

// Catastrophic patterns: rejected instantly without calling Jev.
// Checked against a NORMALIZED command string (lowercased, quotes/
// separators collapsed) so trivial obfuscation does not bypass them.
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
  // rest (host/port/path) visible for debugging context.
  out = out.replace(/([a-zA-Z][a-zA-Z0-9+.-]*:\/\/[^\s/:@]+):([^\s/@]{1,})@/g, "$1:[REDACTED]@")
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

export function isCatastrophic(joined: string): boolean {
  const normalized = normalizeCommand(joined)
  return CATASTROPHIC.some((re) => re.test(joined) || re.test(normalized))
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
  const name = /^[A-Za-z0-9_-]+$/.test(requestID) ? requestID : sha256Hex(requestID)
  try {
    fs.mkdirSync(repliedDirOf(options), { recursive: true })
    fs.writeFileSync(path.join(repliedDirOf(options), name), inst, { flag: "wx" })
    return "won"
  } catch (err) {
    const code = (err as { code?: unknown }).code
    if (code === "EEXIST") return "lost"
    return "error"
  }
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
    z.unref?.()
  } catch {
    // Dialog is best-effort; notify-send alone is enough on headless.
  }
}

function labelsFromFormField(field: unknown): string[] {
  if (!field || typeof field !== "object") return []
  const opts = (field as { options?: unknown }).options
  if (!Array.isArray(opts)) return []
  return opts
    .map((item) => {
      if (typeof item === "string") return item
      const o = item as { label?: unknown; value?: unknown }
      if (typeof o.label === "string" && o.label) return o.label
      if (typeof o.value === "string" && o.value) return o.value
      return null
    })
    .filter((label): label is string => typeof label === "string" && label.length > 0)
    .slice(0, 10)
}

function valueForPick(field: unknown, pick: string): string {
  if (!field || typeof field !== "object") return pick
  const opts = (field as { options?: unknown }).options
  if (!Array.isArray(opts)) return pick
  for (const item of opts) {
    if (typeof item === "string" && item === pick) return pick
    if (item && typeof item === "object") {
      const o = item as { label?: unknown; value?: unknown }
      if (o.label === pick || o.value === pick) {
        return typeof o.value === "string" && o.value ? o.value : pick
      }
    }
  }
  return pick
}

/** List pending interactive forms (question tool uses kind=question forms on 2.0.x). */
function listPendingForms(): Promise<Array<Record<string, unknown>>> {
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

function textOfMessage(message: unknown): ConversationTurn | null {
  if (!message || typeof message !== "object") return null
  const msg = message as { type?: unknown; role?: unknown; text?: unknown; parts?: unknown }
  // v2 shape: { type: "user"|"assistant", text: "..." }. Legacy shape:
  // { role: "user"|"assistant", parts: [{ text }] }.
  const role = msg.type === "user" || msg.role === "user"
    ? "user"
    : msg.type === "assistant" || msg.role === "assistant"
      ? "assistant"
      : null
  if (role === null) return null
  if (typeof msg.text === "string" && msg.text.trim()) return { role, text: msg.text }
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
      ended.add(sessionID)
      return true
    }
    return false
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err)
    if (/not\s*found|unknown session|no such session|deleted|archived/i.test(msg)) {
      ended.add(sessionID)
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
    const msg = err instanceof Error ? err.message : String(err)
    if (/not\s*found|unknown session|no such session|deleted|archived/i.test(msg)) {
      ended.add(sessionID)
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
          formSeen.add(id)
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
          if (dead) endedSessions.add(dead)
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
          if (fid) formSeen.add(fid)
          const task = handleFormAsked(ctx, logEv, inst, options, form, endedSessions)
          void task.catch(() => {
            // Failures are logged inside the handler.
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
          resolved.set(requestID, outcome)
        } catch {
          resolved.set(requestID, { decision: "ask-human", repliedOk: true })
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
      picks.push(decision.pick)
      answer[key] = valueForPick(field, decision.pick)
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

async function handleOne(
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

  // Spawn the gate subprocess before objectiveFor's session.context RPC
  // resolves, not after: its cold start (interpreter init, typesafe_sdk
  // import) then overlaps with that RPC instead of adding to it serially.
  // Every millisecond here is one this permission's reply doesn't get to
  // spend against the server's reply window (issue #15).
  const gate = spawnGate(options)
  const startedAt = Date.now()
  try {
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
