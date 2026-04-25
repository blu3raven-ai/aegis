import { NextRequest, NextResponse } from "next/server"
import { createSession } from "@/lib/server/session"
import { getCurrentUser } from "@/lib/server/auth/server"
import { hashPassword, validatePasswordStrength } from "@/lib/server/auth/passwords.ts"
import { updateOwnAccount, verifyUserPassword } from "@/lib/server/auth/users.ts"

function error(message: string, status: number) {
  return NextResponse.json({ error: message }, { status })
}

export async function PATCH(request: NextRequest) {
  const user = await getCurrentUser()
  if (!user) return error("Unauthorized", 401)

  let body: {
    username?: unknown
    current_password?: unknown
    new_password?: unknown
    confirm_new_password?: unknown
  }

  try {
    body = await request.json()
  } catch {
    return error("Invalid JSON body.", 400)
  }

  const username = String(body.username ?? "").trim()
  const currentPassword = String(body.current_password ?? "")
  const newPassword = String(body.new_password ?? "")
  const confirmNewPassword = String(body.confirm_new_password ?? "")

  if (!username) return error("Username is required.", 400)

  const passwordChangeRequested = Boolean(currentPassword || newPassword || confirmNewPassword)
  let passwordHash: string | undefined

  if (passwordChangeRequested) {
    if (!currentPassword) return error("Current password is required to change password.", 400)
    if (!newPassword) return error("New password is required.", 400)
    if (!confirmNewPassword) return error("Please re-enter the new password.", 400)
    if (newPassword !== confirmNewPassword) return error("New password and confirmation do not match.", 400)
    // Verify current password on the backend — hashes never leave the backend
    const verified = await verifyUserPassword(user.username, currentPassword)
    if (!verified) {
      return error("Current password is incorrect.", 400)
    }
    const strengthError = validatePasswordStrength(newPassword)
    if (strengthError) return error(strengthError, 400)
    passwordHash = await hashPassword(newPassword)
  }

  try {
    const updated = await updateOwnAccount({ id: user.id, username, passwordHash })
    await createSession(updated)
    return NextResponse.json({
      ok: true,
      user: {
        id: updated.id,
        username: updated.username,
        role: updated.role,
        status: updated.status,
      },
    })
  } catch (err) {
    return error(err instanceof Error ? err.message : "Account update failed.", 400)
  }
}
