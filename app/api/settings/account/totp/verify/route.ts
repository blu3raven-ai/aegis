import { NextRequest, NextResponse } from "next/server"
import { requireUser } from "@/lib/server/auth/server"
import { updateTotpSecret } from "@/lib/server/auth/users.ts"
import { writeAuditEvent } from "@/lib/server/auth/audit.ts"
import { verifyTotpCode } from "@/lib/shared/totp"
import { clearPending, getPending } from "../_pending"

export async function POST(request: NextRequest) {
  const userOrResponse = await requireUser()
  if (userOrResponse instanceof NextResponse) return userOrResponse
  const user = userOrResponse

  let code: string
  try {
    const body = await request.json()
    code = String(body.code ?? "").trim()
  } catch {
    return NextResponse.json({ error: "Invalid request body." }, { status: 400 })
  }

  const secret = getPending(user.id)
  if (!secret) {
    return NextResponse.json(
      { error: "Setup session expired. Start over." },
      { status: 400 },
    )
  }

  if (!verifyTotpCode(code, secret)) {
    return NextResponse.json({ error: "Invalid code. Try again." }, { status: 400 })
  }

  await updateTotpSecret(user.id, secret, true)
  clearPending(user.id)
  await writeAuditEvent({
    actorUserId: user.id,
    actorUsername: user.username,
    action: "security.totp_enabled",
    target: user.id,
    metadata: {},
  })
  return NextResponse.json({ ok: true })
}
