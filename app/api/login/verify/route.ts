import { NextRequest, NextResponse } from "next/server"
import { clearMfaSession, getMfaSession } from "@/lib/server/mfa-session"
import { createSession } from "@/lib/server/session"
import { findUserById, verifyTotpOnBackend } from "@/lib/server/auth/users.ts"
import { writeAuditEvent } from "@/lib/server/auth/audit.ts"
import { isRateLimited, recordFailedAttempt, clearRateLimit } from "@/lib/server/rate-limit"

export async function POST(request: NextRequest) {
  const pending = await getMfaSession()
  if (!pending) {
    return NextResponse.json(
      { error: "Session expired. Please sign in again." },
      { status: 401 },
    )
  }

  // Rate limit TOTP attempts per user (5 attempts per 15 min window)
  const rateLimitKey = `totp:${pending.userId}`
  const retryAfter = isRateLimited(rateLimitKey)
  if (retryAfter > 0) {
    return NextResponse.json(
      { error: "Too many verification attempts. Please try again later." },
      { status: 429, headers: { "Retry-After": String(retryAfter) } },
    )
  }

  let code: string
  try {
    const body = await request.json()
    code = String(body.code ?? "").trim()
  } catch {
    return NextResponse.json({ error: "Invalid request body." }, { status: 400 })
  }

  // TOTP verification happens on the backend — secrets never leave the backend
  const verifiedUser = await verifyTotpOnBackend(pending.userId, code)
  if (!verifiedUser) {
    recordFailedAttempt(rateLimitKey)
    await writeAuditEvent({
      actorUserId: pending.userId,
      actorUsername: null,
      action: "login.mfa_failed",
      target: pending.userId,
      metadata: {},
    })
    return NextResponse.json({ error: "Invalid code." }, { status: 400 })
  }

  clearRateLimit(rateLimitKey)
  await clearMfaSession()
  await createSession(verifiedUser)
  await writeAuditEvent({
    actorUserId: verifiedUser.id,
    actorUsername: verifiedUser.username,
    action: "login.mfa_succeeded",
    target: verifiedUser.id,
    metadata: { role: verifiedUser.role },
  })
  return NextResponse.json({ ok: true })
}
