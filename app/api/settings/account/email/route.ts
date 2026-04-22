import { NextRequest, NextResponse } from "next/server"
import { requireUser } from "@/lib/server/auth/server"
import { updateOwnAccount } from "@/lib/server/auth/users.ts"

export async function PATCH(request: NextRequest) {
  const userOrResponse = await requireUser()
  if (userOrResponse instanceof NextResponse) return userOrResponse
  const user = userOrResponse

  let email: string | null
  try {
    const body = await request.json() as { email?: unknown }
    email = typeof body.email === "string" ? body.email.trim() || null : null
  } catch {
    return NextResponse.json({ error: "Invalid request body" }, { status: 400 })
  }

  if (email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return NextResponse.json({ error: "Invalid email address" }, { status: 400 })
  }

  await updateOwnAccount({ id: user.id, username: user.username, email })
  return NextResponse.json({ ok: true })
}
