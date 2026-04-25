import { NextResponse } from "next/server"
import { getCurrentUser } from "@/lib/server/auth/server"

export async function GET() {
  const user = await getCurrentUser()
  if (!user) {
    return NextResponse.json({ user: null }, { status: 401 })
  }

  return NextResponse.json({
    user: {
      id: user.id,
      username: user.username,
      email: user.email ?? null,
      role: user.role,
      status: user.status,
      totpEnabled: user.totpEnabled ?? false,
      passwordResetRequired: user.passwordResetRequired,
      avatarUrl: user.avatarUrl ?? null,
    },
  })
}
