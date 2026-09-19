import { Plugin } from "@opencode/plugin"
import { spawn } from "node:child_process"
import fs from "node:fs"
import path from "node:path"
import { fileURLToPath } from "node:url"

// Catastrophic patterns: rejected instantly without calling Jev.
const CATASTROPHIC = [
  /\brm\s+-rf\s+\/(?!\S)/,
  /\brm\s+-rf\s+\/\*/,
  /\bmkfs\b/,
  /\bdd\b\s+.*\bof=\/dev\//,
  /\bshutdown\b/,
  /\breboot\b/,
  /\bchmod\s+(-R\s+)?777\s+\//,
  /:\(\)\s*\{\s*:\|\:&\s*\}\s*;/,
  /\bsudo\s+rm\s+-rf\s+~?\/?(?!\S)/,
]

const DESTRUCTIVE_HINT = /(^|\s)(rm\s+-rf|sudo|git\s+push|git\s+reset\s+--hard|git\s+clean\s+-fd?|kubectl\s+delete|terraform\s+(apply|destroy)|npm\s+publish|cargo\s+publish|drop\s+(table|database))/i

function kindFor(action: string, resources: string[]): string | null {
  if (action === "question") return "multichoice"
  if (action === "read" || action === "glob" || action === "grep" || action === "external_directory") return "read"
  if (action === "edit") return "write"
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
        if (labels.length > 0) return labels
      }
    } catch {
      continue
    }
  }
  return []
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

function logFileOf(options: Record<string, unknown>): string {
  if (typeof options.logFile === "string" && options.logFile) return options.logFile
  if (process.env.JEV_GATE_LOG) return process.env.JEV_GATE_LOG
  return path.join(repoRoot(options), "decisions-plugin.jsonl")
}

function logLine(options: Record<string, unknown>, entry: Record<string, unknown>): void {
  try {
    fs.appendFileSync(logFileOf(options), JSON.stringify(entry) + "\n")
  } catch {
    // Logging must never break the permission flow.
  }
}

function runGate(options: Record<string, unknown>, event: Record<string, unknown>): Promise<Record<string, unknown>> {
  return new Promise((resolve, reject) => {
    const child = spawn("python3", ["-m", "jev_gate.cli"], {
      cwd: repoRoot(options),
      env: { ...process.env, TYPESAFE_API_KEY: apiKeyOf(options), JEV_GATE_LOG: logFileOf(options) },
    })
    let stdout = ""
    let stderr = ""
    const timer = setTimeout(() => {
      try {
        child.kill("SIGKILL")
      } catch {
        // ignore
      }
      reject(new Error("gate timeout"))
    }, 15000)
    child.stdout.on("data", (chunk) => {
      stdout += String(chunk)
    })
    child.stderr.on("data", (chunk) => {
      stderr += String(chunk)
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

async function objectiveFor(ctx: { session: { context: (input: { sessionID: string }) => Promise<unknown> } }, sessionID: string): Promise<string> {
  try {
    const messages = await ctx.session.context({ sessionID })
    const list = Array.isArray(messages) ? messages : []
    const userTexts = list
      .map(textOfMessage)
      .filter((t): t is string => t !== null)
      .join("\n")
      .slice(-800)
    return userTexts || "Complete the assigned coding task"
  } catch {
    return "Complete the assigned coding task"
  }
}

export default Plugin.define({
  id: "jev-decision-gate",
  async setup(ctx) {
    const options = ((ctx as { options?: unknown }).options ?? {}) as Record<string, unknown>
    if (!isEnabled(options)) return
    const controller = new AbortController()
    void (async () => {
      try {
        for await (const event of ctx.event.subscribe({ signal: controller.signal })) {
        const evt = event as { type?: string; data?: Record<string, unknown> }
        if (evt.type !== "permission.asked") continue
        const data = evt.data ?? {}
        const sessionID = String(data.sessionID ?? "")
        const requestID = String(data.id ?? "")
        const action = String((data as { action?: unknown }).action ?? "")
        const resources = Array.isArray((data as { resources?: unknown }).resources)
          ? ((data as { resources: unknown[] }).resources.map(String))
          : []
        if (!sessionID || !requestID) continue

        const joined = resources.join("\n")
        if (CATASTROPHIC.some((re) => re.test(joined))) {
          logLine(options, { action: "reject", reason: "catastrophic-pattern", tool: action })
          try {
            await ctx.permission.reply({ sessionID, requestID, reply: "reject" })
          } catch {
            // Fall through to the human prompt.
          }
          continue
        }

        const kind = kindFor(action, resources)
        if (kind === null) continue

        try {
          const objective = await objectiveFor(ctx, sessionID)
          const halt: Record<string, unknown> = { kind, tool: action, detail: joined.slice(0, 4000) }
          if (kind === "multichoice") {
            const options = parseOptions(resources)
            if (options.length > 0) halt.options = options
          }
          const gateEvent = {
            objective,
            halt,
            context: { sessionID },
            policy: { default: "ask-human when unsure" },
          }
          const startedAt = Date.now()
          const decision = await runGate(options, gateEvent)
          const elapsedMs = Date.now() - startedAt
          logLine(options, {
            tool: action,
            gateAction: decision.action,
            reason: decision.reason,
            confidence: decision.confidence,
            model: decision.model,
            pick: decision.pick ?? null,
            elapsedMs,
            objectiveChars: objective.length,
            hasKey: apiKeyOf(options) !== "",
          })
          if (decision.action === "allow") {
            await ctx.permission.reply({ sessionID, requestID, reply: "once" })
          } else if (decision.action === "deny") {
            await ctx.permission.reply({ sessionID, requestID, reply: "reject" })
          }
          // ask-human: no reply, the human prompt appears.
        } catch {
          // Fail silent: the human prompt appears.
        }
      }
      } catch {
        // Subscription ended (server shutdown). Nothing to report.
      }
    })()
    return () => controller.abort()
  },
})
