import { NextResponse } from "next/server"
import { requireUser } from "@/lib/server/auth/server"
import { updateOwnAccount } from "@/lib/server/auth/users.ts"

const MAX_AVATAR_SIZE = 150_000

export async function POST(request: Request) {
  const userOrResponse = await requireUser()
  if (userOrResponse instanceof NextResponse) return userOrResponse
  const user = userOrResponse

  try {
    const body = await request.json()
    const avatarUrl = String(body.avatarUrl ?? "")

    const ALLOWED_PREFIXES = ["data:image/png", "data:image/jpeg", "data:image/gif", "data:image/webp"]
    if (avatarUrl && !ALLOWED_PREFIXES.some((p) => avatarUrl.startsWith(p))) {
      return NextResponse.json({ error: "Only PNG, JPEG, GIF, and WebP images are allowed." }, { status: 400 })
    }
    if (avatarUrl.length > MAX_AVATAR_SIZE) {
      return NextResponse.json({ error: "Image too large. Max 100KB." }, { status: 400 })
    }

    await updateOwnAccount({ id: user.id, username: user.username, avatarUrl: avatarUrl || null })
    return NextResponse.json({ ok: true })
  } catch (e: any) {
    return NextResponse.json({ error: e.message || "Failed to update avatar." }, { status: 500 })
  }
}

export async function DELETE() {
  const userOrResponse = await requireUser()
  if (userOrResponse instanceof NextResponse) return userOrResponse
  const user = userOrResponse

  try {
    await updateOwnAccount({ id: user.id, username: user.username, avatarUrl: "" })
    return NextResponse.json({ ok: true })
  } catch (e: any) {
    return NextResponse.json({ error: e.message || "Failed to remove avatar." }, { status: 500 })
  }
}
