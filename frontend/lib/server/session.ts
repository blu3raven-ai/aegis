import "server-only"

import { cookies } from "next/headers"
import type { UserRole } from "@/lib/shared/auth/roles"

const FASTAPI_URL = process.env.FASTAPI_URL ?? "http://localhost:8000"
const SESSION_COOKIE_NAME = "__Host-session"

export interface SessionPayload {
  userId: string
  username: string | null
  role: UserRole
  roleId?: string | null
  status: string
  sessionVersion: number
}

/** Read the current session by calling /auth/me on FastAPI. Returns null if unauthenticated. */
export async function getSession(): Promise<SessionPayload | null> {
  const cookieStore = await cookies()
  const sessionCookie = cookieStore.get(SESSION_COOKIE_NAME)
  if (!sessionCookie) return null

  try {
    const response = await fetch(`${FASTAPI_URL}/auth/me`, {
      headers: { Cookie: `${SESSION_COOKIE_NAME}=${sessionCookie.value}` },
      cache: "no-store",
    })
    if (!response.ok) return null
    const body = await response.json()
    const user = body.user
    if (!user) return null
    return {
      userId: user.id,
      username: user.username ?? null,
      role: (user.role ?? "viewer") as UserRole,
      roleId: user.roleId ?? null,
      status: user.status ?? "active",
      sessionVersion: user.sessionVersion ?? 1,
    }
  } catch {
    return null
  }
}

/** Forward the session cookie header for server-side FastAPI requests. Returns null if no session. */
export async function getSessionCookieHeader(): Promise<string | null> {
  const cookieStore = await cookies()
  const sessionCookie = cookieStore.get(SESSION_COOKIE_NAME)
  if (!sessionCookie) return null
  return `${SESSION_COOKIE_NAME}=${sessionCookie.value}`
}
