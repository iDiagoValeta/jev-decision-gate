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
  /\brm\s+(-[a-z]*r[a-z]*f|-[a-z]*f[a-z]*r)\s+(\S*\s+)*(\/(?!\S)|\/\*|~(?!\S)|~\/|\$home(\/\S*)?|\${home}[^\s]*|\/home(?!\S)|\.(\/\S*)?)/,
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

const SECRET_PATTERNS: RegExp[] = [
  /bearer\s+[A-Za-z0-9\-._~+/=]{8,}/gi,
  /basic\s+[A-Za-z0-9+/=]{8,}/gi,
  /\bAKIA[0-9A-Z]{16}\b/g,
  /\b(ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|sk-[A-Za-z0-9\-_]{8,}|xox[bpas]-[A-Za-z0-9\-_]{8,})\b/g,
  /-----BEGIN [A-Z ]*PRIVATE KEY-----/g,
]

export function normalizeCommand(text: string): string {
  return text
    .toLowerCase()
    .replace(/["'`]/g, "")
    .replace(/\$\{ifs\}/g, " ")
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
  return out.replace(
    /((?:typesafe[_-]?api[_-]?key|api[_-]?key|password|passwd|secret|token)\s*[:=]\s*)([^\s"']{4,})/gi,
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

export function kindFor(action: string, resources: string[]): string | null {
  if (action === "question") return "multichoice"
  if (action === "read" || action === "glob" || action === "grep" || action === "external_directory") return "read"
  if (action === "edit") {
    const text = resources.join("\n")
    if (DESTRUCTIVE_HINT.test(text)) return "destructive"
    return "write"
  }
  const text = resources.join("\n")
  if (DESTRUCTIVE_HINT.test(text)) return "destructive"
  return "write"
}

function parseOptions(resources: string[]): string[] {
  for (const resource of resources) {
    try {
      const parsed: unknown = JSON.parse(resource)
      const list = Array.isArray(parsed) ? parsed : (parsed as { options?: unknown }).options
      if (Array.isArray(list)) {
        const labels = list
          .map((item) => (typeof item === "string" ? item : (item as { label?: unknown }).label))
          .filter((label): label is string => typeof label === "string" && label.length > 0)
        if (labels.length > 0) return labels.slice(0, 10)
      }
    } catch {
      continue
    }
  }
  return []
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

// Cross-instance reply claim: setup() may run more than once per
// process (and several processes may share a gateDir), so in-memory
// maps alone cannot guarantee a single reply. First claimant wins via
// an exclusive marker file; losers skip the reply.
function repliedDirOf(options: Record<string, unknown>): string {
  return path.join(repoRoot(options), ".jev-gate-replied")
}

// Returns "won" (reply now), "lost" (someone else owns it) or "error"
// (marker unusable — reply anyway, never suppress on FS trouble).
function claimReply(options: Record<string, unknown>, requestID: string, inst: string): "won" | "lost" | "error" {
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

function releaseReply(options: Record<string, unknown>, requestID: string): void {
  const name = /^[A-Za-z0-9_-]+$/.test(requestID) ? requestID : sha256Hex(requestID)
  try {
    fs.unlinkSync(path.join(repliedDirOf(options), name))
  } catch {
    // Best effort: a stale marker only risks one extra reply attempt.
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
function minimalEnv(options: Record<string, unknown>): Record<string, string | undefined> {
  return {
    PATH: process.env.PATH,
    HOME: process.env.HOME,
    PYTHONPATH: process.env.PYTHONPATH,
    TYPESAFE_API_KEY: apiKeyOf(options),
    JEV_GATE_LOG: logFileOf(options),
    JEV_GATE_CLI_LOG: "0",
    JEV_MODEL: process.env.JEV_MODEL,
    JEV_GATE_DIR: process.env.JEV_GATE_DIR,
  }
}

function runGate(options: Record<string, unknown>, event: Record<string, unknown>): Promise<Record<string, unknown>> {
  return new Promise((resolve, reject) => {
    const child = spawn("python3", ["-m", "jev_gate.cli"], {
      cwd: repoRoot(options),
      env: minimalEnv(options),
    })
    let stdout = ""
    let stderr = ""
    const CAP = 256 * 1024
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
      reject(new Error("gate timeout"))
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
      reject(error)
    })
    child.on("close", (code) => {
      clearTimeout(timer)
      if (code !== 0) {
        reject(new Error("gate exit " + String(code) + " " + stderr.slice(0, 200)))
        return
      }
      try {
        resolve(JSON.parse(stdout) as Record<string, unknown>)
      } catch (parseError) {
        reject(parseError)
      }
    })
    try {
      child.stdin.write(JSON.stringify(event))
      child.stdin.end()
    } catch (stdinError) {
      clearTimeout(timer)
      reject(stdinError)
    }
  })
}

function textOfMessage(message: unknown): string | null {
  if (!message || typeof message !== "object") return null
  const msg = message as { type?: unknown; role?: unknown; text?: unknown; parts?: unknown }
  // v2 shape: { type: "user", text: "..." }. Legacy shape: { role: "user", parts: [{ text }] }.
  if (msg.type !== "user" && msg.role !== "user") return null
  if (typeof msg.text === "string" && msg.text.trim()) return msg.text
  if (Array.isArray(msg.parts)) {
    const text = msg.parts
      .filter((p): p is { text?: unknown } => !!p && typeof p === "object")
      .filter((p) => typeof p.text === "string")
      .map((p) => p.text as string)
      .join("\n")
    if (text.trim()) return text
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
): Promise<string> {
  try {
    const messages = await ctx.session.context({ sessionID })
    const list = Array.isArray(messages) ? messages : []
    const userTexts = list
      .map(textOfMessage)
      .filter((t): t is string => t !== null)
    const last = userTexts.slice(-3).join("\n").slice(-500)
    const redacted = redactSecrets(last)
    return redacted || "Complete the assigned coding task"
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
    void (async () => {
      try {
        for await (const event of ctx.event.subscribe({ signal: controller.signal })) {
        const evt = event as { type?: string; data?: Record<string, unknown> }
        if (evt.type === "session.deleted") {
          const dead = String((evt.data ?? {}).sessionID ?? "")
          if (dead) endedSessions.add(dead)
          continue
        }
        if (evt.type !== "permission.asked") continue
        const data = evt.data ?? {}
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
              await ctx.permission.reply({
                sessionID,
                requestID,
                decision: cached.decision === "allow" ? "once" : "reject",
              })
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
    return () => controller.abort()
  },
})

async function handleOne(
  ctx: { permission: { reply: (input: { sessionID: string; requestID: string; decision: "once" | "reject" }) => Promise<unknown> }; session: { get?: (input: { sessionID: string }) => Promise<unknown>; context: (input: { sessionID: string }) => Promise<unknown> } },
  log: (entry: Record<string, unknown>) => void,
  inst: string,
  options: Record<string, unknown>,
  sessionID: string,
  requestID: string,
  action: string,
  resources: string[],
  endedSessions: Set<string>,
): Promise<{ decision: string; repliedOk: boolean }> {
  const joined = resources.join("\n")
  const resKinds = resourceKinds(resources)
  if (isCatastrophic(joined)) {
    log({ sessionID, requestID, tool: action, kind: "destructive", gateAction: "reject", reason: "catastrophic-pattern", detail_sha256: sha256Hex(joined) })
    let repliedOk = false
    const claim = claimReply(options, requestID, inst)
    if (claim !== "lost") {
      try {
        await ctx.permission.reply({ sessionID, requestID, decision: "reject" })
        repliedOk = true
      } catch {
        if (claim === "won") releaseReply(options, requestID)
        // Fall through to the human prompt.
      }
    } else {
      repliedOk = true
    }
    return { decision: "deny", repliedOk }
  }

  const kind = kindFor(action, resources)
  if (kind === null) return { decision: "ask-human", repliedOk: true }

  try {
    const objective = await objectiveFor(ctx, sessionID, endedSessions)
    const rawDetail = joined.slice(0, 4000)
    const detail = redactSecrets(rawDetail)
    const riskHints = DESTRUCTIVE_HINT.test(joined) ? "matches destructive-hint" : ""
    const halt: Record<string, unknown> = { kind, tool: action, detail }
    if (kind === "multichoice") {
      const opts = parseOptions(resources)
      if (opts.length > 0) {
        halt.options = opts
        halt.numbered = numberedOptions(opts)
      }
    }
    const gateEvent = {
      objective,
      halt,
      context: { sessionID, requestID, risk_hints: riskHints },
      policy: { default: "ask-human when unsure" },
    }
    const startedAt = Date.now()
    const decision = await runGate(options, gateEvent)
    const elapsedMs = Date.now() - startedAt
    const optsLogged = kind === "multichoice" ? (halt.options as string[] | undefined)?.length ?? 0 : undefined
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
      ...(optsLogged !== undefined ? { optionsCount: optsLogged } : {}),
      ...(typeof decision.error === "string" ? { error_class: decision.error } : {}),
    })
    let repliedOk = true
    if (decision.action === "allow" || decision.action === "deny") {
      const claim = claimReply(options, requestID, inst)
      if (claim === "lost") {
        log({ sessionID, requestID, tool: action, gateAction: decision.action, reason: "duplicate-suppressed" })
        return { decision: String(decision.action), repliedOk: true }
      }
      try {
        await ctx.permission.reply({ sessionID, requestID, decision: decision.action === "allow" ? "once" : "reject" })
      } catch (err) {
        if (claim === "won") releaseReply(options, requestID)
        log({ sessionID, requestID, tool: action, gateAction: decision.action, reason: "reply-failed", error_class: err instanceof Error ? err.message.slice(0, 120) : "exception" })
        repliedOk = false
      }
    }
    // ask-human: no reply, the human prompt appears.
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
    // Fail silent: the human prompt appears.
    return { decision: "ask-human", repliedOk: true }
  }
}
