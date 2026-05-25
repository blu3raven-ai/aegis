import "server-only"

import { NextResponse } from "next/server"
import { getSession } from "@/lib/server/session"
import { can, type Permission, type UserRole } from "@/lib/shared/auth/roles.ts"
import { findUserById, type DashboardUser } from "@/lib/server/auth/users.ts"
import { fetchPolicyServer } from "@/lib/server/settings-api"

export async function getCurrentUser(): Promise<DashboardUser | null> {
  const session = await getSession()
  if (!session) return null
  const user = await findUserById(session.userId)
  if (!user || user.status === "disabled") return null
  return user
}

export async function requireActiveUser(): Promise<DashboardUser | NextResponse> {
  const user = await getCurrentUser()
  if (!user || user.status !== "active") {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 })
  }
  return user
}

export async function requireUser(): Promise<DashboardUser | NextResponse> {
  const user = await getCurrentUser()
  if (!user) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 })
  }
  return user
}

export async function requirePermission(permission: Permission): Promise<DashboardUser | NextResponse> {
  const user = await requireActiveUser()
  if (user instanceof NextResponse) return user
  
  if (user.role === "owner") return user

  const policy = await fetchPolicyServer({ id: user.id, role: user.role, roleId: user.roleId })

  if (!can(user.role, permission, policy as any)) {
    return NextResponse.json({ error: "Forbidden" }, { status: 403 })
  }
  return user
}

export async function requireAuthenticatedUser() {
  const session = await getSession()
  return session ? { id: session.userId, role: session.role as UserRole } : new Response(null, { status: 401 })
}
