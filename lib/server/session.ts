import "server-only"

import { cookies } from "next/headers"
import { decryptSession, encryptSession, type SessionPayload } from "@/lib/server/session-token"
import type { DashboardUser } from "@/lib/server/auth/users.ts"
import { findUserById } from "@/lib/server/auth/users.ts"
import { createLogger } from "@/lib/server/logger"

const log = createLogger("session")

const COOKIE_NAME = "__session"
const SESSION_DURATION_S = 60 * 60 * 24 // 24 hours

export function getSessionCookieOptions() {
  return {
    httpOnly: true,
    sameSite: "strict" as const,
    path: "/",
    maxAge: SESSION_DURATION_S,
    secure: process.env.NODE_ENV === "production",
  }
}

/** Set the session cookie. Call only from Route Handlers. */
export async function createSession(user: DashboardUser): Promise<void> {
  const payload: SessionPayload = {
    userId: user.id,
    username: user.username,
    role: user.role,
    roleId: user.roleId,
    status: user.status,
    sessionVersion: user.sessionVersion,
    exp: Math.floor(Date.now() / 1000) + SESSION_DURATION_S,
  }
  const token = encryptSession(payload)
  const cookieStore = await cookies()
  cookieStore.set(COOKIE_NAME, token, getSessionCookieOptions())
}

/** Read and decrypt the session cookie. Returns null if missing or invalid. */
export async function getSession(): Promise<SessionPayload | null> {
  const cookieStore = await cookies()
  const token = cookieStore.get(COOKIE_NAME)?.value
  if (!token) return null
  const payload = decryptSession(token)
  if (!payload) {
    log.warn("Decryption failed")
    return null
  }
  const user = await findUserById(payload.userId)
  if (!user) {
    log.warn("User not found:", payload.userId)
    return null
  }
  if (user.status === "disabled") {
    log.warn("User disabled:", payload.userId)
    return null
  }
  if (user.sessionVersion !== (payload.sessionVersion ?? 1)) {
    log.warn("Session version mismatch — invalidating:", payload.userId)
    return null
  }
  // Profile fields (username, role, status) may change between requests.
  // Return the current DB state rather than invalidating the session,
  // so the user isn't logged out after updating their own profile.
  if (
    user.username !== payload.username ||
    user.role !== payload.role ||
    (user.roleId ?? null) !== (payload.roleId ?? null) ||
    user.status !== payload.status
  ) {
    log.info("Session payload stale — using DB values:", payload.userId)
    return {
      ...payload,
      username: user.username,
      role: user.role,
      roleId: user.roleId,
      status: user.status,
    }
  }
  return payload
}

/** Clear the session cookie. Call only from Route Handlers. */
export async function deleteSession(): Promise<void> {
  const cookieStore = await cookies()
  cookieStore.set(COOKIE_NAME, "", { maxAge: 0, path: "/" })
}
