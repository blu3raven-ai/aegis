import { NextRequest, NextResponse } from "next/server"
import { createSession } from "@/lib/server/session"
import { createMfaSession } from "@/lib/server/mfa-session"
import { readAppConfig } from "@/lib/server/app-config"
import { migrateSingleUserConfig, verifyUserPassword } from "@/lib/server/auth/users.ts"
import { writeAuditEvent } from "@/lib/server/auth/audit.ts"
import { isRateLimited, recordFailedAttempt, clearRateLimit } from "@/lib/server/rate-limit"

export async function POST(request: NextRequest) {
  let username = ""
  let password = ""

  try {
    const body = await request.json()
    username = String(body.identifier ?? body.username ?? "").trim()
    password = String(body.password ?? "")
  } catch {
    return NextResponse.json({ error: "Invalid request body" }, { status: 400 })
  }

  // Rate limit by username and IP
  const ip = request.headers.get("x-forwarded-for")?.split(",")[0]?.trim() || "unknown"
  const retryAfterUser = isRateLimited(`login:user:${username.toLowerCase()}`)
  const retryAfterIp = isRateLimited(`login:ip:${ip}`)
  const retryAfter = Math.max(retryAfterUser, retryAfterIp)
  if (retryAfter > 0) {
    return NextResponse.json(
      { error: "Too many login attempts. Please try again later." },
      { status: 429, headers: { "Retry-After": String(retryAfter) } },
    )
  }

  const config = readAppConfig()
  if (config.dashboard.username && config.dashboard.password) {
    await migrateSingleUserConfig({
      username: config.dashboard.username,
      email: config.dashboard.email,
      password: config.dashboard.password,
    })
  }

  // Password verification happens on the backend — hashes never leave the backend
  const user = await verifyUserPassword(username, password, { activeOnly: true })

  if (!user) {
    recordFailedAttempt(`login:user:${username.toLowerCase()}`)
    recordFailedAttempt(`login:ip:${ip}`)
    await writeAuditEvent({
      actorUserId: null,
      actorUsername: username || null,
      action: "login.failed",
      target: username || null,
      metadata: { reason: "invalid_credentials" },
    })
    return NextResponse.json({ error: "Invalid username, email, or password" }, { status: 401 })
  }

  clearRateLimit(`login:user:${username.toLowerCase()}`)
  clearRateLimit(`login:ip:${ip}`)

  if (user.totpEnabled || user.mfaEnabled) {
    await createMfaSession(user.id)
    return NextResponse.json({ requiresMfa: true })
  }

  await createSession(user)
  await writeAuditEvent({
    actorUserId: user.id,
    actorUsername: user.username,
    action: "login.succeeded",
    target: user.id,
    metadata: { role: user.role },
  })
  return NextResponse.json({ ok: true })
}
