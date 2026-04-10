import { postJson } from "../internal-api.ts"
import { createLogger } from "@/lib/server/logger"

const log = createLogger("audit")

const SERVICE_USER = { id: "system", role: "owner" as const }

let testAuditPath: string | null = null

export function setAuditPathForTests(filePath: string | null) {
  testAuditPath = filePath
}

function redactMetadata(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(redactMetadata)
  if (!value || typeof value !== "object") return value
  const out: Record<string, unknown> = {}
  for (const [key, entry] of Object.entries(value)) {
    const lower = key.toLowerCase()
    if (lower.includes("token") || lower.includes("password") || lower.includes("secret")) {
      out[key] = "[redacted]"
    } else {
      out[key] = redactMetadata(entry)
    }
  }
  return out
}

export async function writeAuditEvent(input: {
  actorUserId: string | null
  actorUsername: string | null
  action: string
  target: string | null
  metadata: Record<string, unknown>
}) {
  try {
    await postJson("/auth/internal/audit", SERVICE_USER, {
      actorUserId: input.actorUserId,
      actorUsername: input.actorUsername,
      action: input.action,
      target: input.target,
      metadata: redactMetadata(input.metadata),
    })
  } catch (err) {
    // Don't let audit failures break the calling operation
    log.error("Failed to write event:", err)
  }
}
