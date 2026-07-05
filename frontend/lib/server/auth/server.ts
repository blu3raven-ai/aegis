import "server-only"

import { NextResponse } from "next/server"
import { getSession, type SessionPayload } from "@/lib/server/session"
import type { UserRole } from "@/lib/shared/auth/roles.ts"

// Minimal user shape consumed by server pages.
// Fields align with what /api/v1/auth/me returns via getSession().
export interface SessionUser {
  id: string
  username: string | null
  email?: string | null
  role: UserRole
  roleId?: string | null
  status: string
  sessionVersion: number
}

function sessionToUser(session: SessionPayload): SessionUser {
  return {
    id: session.userId,
    username: session.username,
    role: session.role as UserRole,
    roleId: session.roleId ?? null,
    status: session.status,
    sessionVersion: session.sessionVersion,
  }
}

export async function getCurrentUser(): Promise<SessionUser | null> {
  const session = await getSession()
  if (!session) return null
  if (session.status === "disabled") return null
  return sessionToUser(session)
}

export async function requireActiveUser(): Promise<SessionUser | NextResponse> {
  const user = await getCurrentUser()
  if (!user || user.status !== "active") {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 })
  }
  return user
}

export async function requireUser(): Promise<SessionUser | NextResponse> {
  const user = await getCurrentUser()
  if (!user) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 })
  }
  return user
}

export async function requireAuthenticatedUser() {
  const session = await getSession()
  return session ? { id: session.userId, role: session.role as UserRole } : new Response(null, { status: 401 })
}
