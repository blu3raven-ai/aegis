import { NextResponse } from "next/server"
import QRCode from "qrcode"
import { requireUser } from "@/lib/server/auth/server"
import { updateTotpSecret } from "@/lib/server/auth/users.ts"
import { writeAuditEvent } from "@/lib/server/auth/audit.ts"
import { buildOtpauthUri, generateTotpSecret } from "@/lib/shared/totp"
import { setPending } from "./_pending"
import { getJson } from "@/lib/server/internal-api"

export async function POST() {
  const userOrResponse = await requireUser()
  if (userOrResponse instanceof NextResponse) return userOrResponse
  const user = userOrResponse

  try {
    const status = await getJson<{ tier: string }>("/license/api/status", user)
    if (status.tier !== "enterprise") {
      return NextResponse.json({ error: "MFA requires an Enterprise license." }, { status: 403 })
    }
  } catch {
    return NextResponse.json({ error: "Could not verify license status." }, { status: 500 })
  }

  const secret = generateTotpSecret()
  const uri = buildOtpauthUri(secret, user.username)
  const qrDataUrl = await QRCode.toDataURL(uri)

  setPending(user.id, secret)

  return NextResponse.json({ qrDataUrl, secret })
}

export async function DELETE(request: Request) {
  const userOrResponse = await requireUser()
  if (userOrResponse instanceof NextResponse) return userOrResponse
  const user = userOrResponse

  // Require password confirmation to disable MFA
  let password = ""
  try {
    const body = await request.json()
    password = String(body.password ?? "")
  } catch {
    return NextResponse.json({ error: "Password required to disable MFA." }, { status: 400 })
  }

  const { verifyUserPassword } = await import("@/lib/server/auth/users.ts")
  if (!password || !(await verifyUserPassword(user.username, password))) {
    return NextResponse.json({ error: "Invalid password." }, { status: 403 })
  }

  await updateTotpSecret(user.id, null, false)
  await writeAuditEvent({
    actorUserId: user.id,
    actorUsername: user.username,
    action: "security.totp_disabled",
    target: user.id,
    metadata: {},
  })
  return NextResponse.json({ ok: true })
}
