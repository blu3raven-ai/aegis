import { hashPassword } from "./passwords.ts"
import { getJson, postJson } from "../internal-api.ts"
import type { UserRole } from "../../shared/auth/roles.ts"

export type UserStatus = "active" | "disabled" | "pending"

export interface DashboardUser {
  id: string
  username: string
  email?: string | null
  passwordHash?: string
  role: UserRole
  roleId?: string | null
  status: UserStatus
  passwordResetRequired: boolean
  createdAt: string
  updatedAt: string
  totpSecret?: string | null
  totpEnabled?: boolean
  mfaEnabled?: boolean
  avatarUrl?: string | null
  sessionVersion: number
}

// Internal user object for API calls — uses a service account identity
const SERVICE_USER = { id: "system", role: "owner" as const }

function toDashboardUser(raw: any): DashboardUser {
  return {
    id: raw.id,
    username: raw.username,
    email: raw.email ?? null,
    passwordHash: raw.passwordHash ?? "",
    role: raw.role ?? "viewer",
    roleId: raw.roleId ?? null,
    status: raw.status ?? "active",
    passwordResetRequired: raw.passwordResetRequired ?? false,
    createdAt: raw.createdAt ?? "",
    updatedAt: raw.updatedAt ?? "",
    totpSecret: raw.totpSecret ?? null,
    totpEnabled: raw.totpEnabled ?? raw.mfaEnabled ?? false,
    mfaEnabled: raw.mfaEnabled ?? raw.totpEnabled ?? false,
    avatarUrl: raw.avatarUrl || null,
    sessionVersion: raw.sessionVersion ?? 1,
  }
}

// Keep for test compatibility
let testUserStorePath: string | null = null
export function setUserStorePathForTests(filePath: string | null) {
  testUserStorePath = filePath
}

export async function listUsers(): Promise<DashboardUser[]> {
  const data = await getJson<{ users: any[] }>("/settings/api/users", SERVICE_USER)
  return Array.isArray(data.users) ? data.users.map(toDashboardUser) : []
}

export async function findUserByUsername(
  username: string,
  opts: { activeOnly?: boolean } = {}
): Promise<DashboardUser | null> {
  try {
    const data = await postJson<{ user: any | null }>("/auth/internal/lookup", SERVICE_USER, {
      username: username.trim(),
    })
    if (!data.user) return null
    const user = toDashboardUser(data.user)
    if (opts.activeOnly && user.status !== "active") return null
    return user
  } catch {
    return null
  }
}

export async function findUserByEmail(
  email: string,
  opts: { activeOnly?: boolean } = {}
): Promise<DashboardUser | null> {
  // The lookup endpoint searches both username and email
  return findUserByUsername(email, opts)
}

// Cache user lookups to avoid HTTP call on every getSession()
const _userCache = new Map<string, { user: DashboardUser; time: number }>()
const USER_CACHE_TTL = 10_000 // 10 seconds

export async function findUserById(id: string): Promise<DashboardUser | null> {
  const cached = _userCache.get(id)
  if (cached && Date.now() - cached.time < USER_CACHE_TTL) {
    return cached.user
  }
  try {
    const data = await getJson<{ user: any }>(`/auth/internal/user/${encodeURIComponent(id)}`, SERVICE_USER)
    if (!data.user) return null
    const user = toDashboardUser(data.user)
    _userCache.set(id, { user, time: Date.now() })
    return user
  } catch {
    // If backend is down, return cached value even if stale
    return cached?.user ?? null
  }
}

/**
 * Verify a user's password on the backend. Returns the user if valid, null if not.
 * Password hashes never leave the backend — verification happens server-side.
 */
export async function verifyUserPassword(
  username: string,
  password: string,
  opts: { activeOnly?: boolean } = {}
): Promise<DashboardUser | null> {
  try {
    const data = await postJson<{ user: any | null; valid: boolean }>(
      "/auth/internal/verify-password",
      SERVICE_USER,
      { username: username.trim(), password },
    )
    if (!data.valid || !data.user) return null
    const user = toDashboardUser(data.user)
    if (opts.activeOnly && user.status !== "active") return null
    return user
  } catch {
    return null
  }
}

/**
 * Verify a TOTP code on the backend. Returns the user if valid, null if not.
 * TOTP secrets never leave the backend — verification happens server-side.
 */
export async function verifyTotpOnBackend(
  userId: string,
  code: string,
): Promise<DashboardUser | null> {
  try {
    const data = await postJson<{ user: any | null; valid: boolean }>(
      "/auth/internal/verify-totp",
      SERVICE_USER,
      { userId, code },
    )
    if (!data.valid || !data.user) return null
    return toDashboardUser(data.user)
  } catch {
    return null
  }
}

export async function createUser(input: {
  username: string
  password: string
  role: UserRole
}): Promise<DashboardUser> {
  const username = input.username.trim()
  if (!username) throw new Error("Username is required.")
  if (!input.password.trim()) throw new Error("Password is required.")

  const data = await postJson<{ user: any; ok: boolean }>("/settings/api/users", SERVICE_USER, {
    username,
    email: "",
    password: input.password,
    role: input.role,
  })
  return toDashboardUser(data.user)
}

export async function updateOwnAccount(input: {
  id: string
  username: string
  email?: string | null
  passwordHash?: string
  passwordResetRequired?: boolean
  avatarUrl?: string | null
}): Promise<DashboardUser> {
  const username = input.username.trim()
  if (!username) throw new Error("Username is required.")

  const body: Record<string, unknown> = { username }
  if ("email" in input) body.email = input.email ?? ""
  if (input.passwordHash) body.passwordHash = input.passwordHash
  if (input.passwordResetRequired !== undefined) body.passwordResetRequired = input.passwordResetRequired
  if ("avatarUrl" in input) body.avatarUrl = input.avatarUrl ?? ""

  const data = await postJson<{ user: any }>(
    `/auth/internal/user/${encodeURIComponent(input.id)}/account`,
    SERVICE_USER,
    body,
    "PATCH",
  )
  return toDashboardUser(data.user)
}

export async function updateTotpSecret(
  id: string,
  totpSecret: string | null,
  totpEnabled: boolean,
): Promise<DashboardUser> {
  const data = await postJson<{ user: any }>(
    `/auth/internal/user/${encodeURIComponent(id)}/totp`,
    SERVICE_USER,
    { totpSecret, totpEnabled },
    "PATCH",
  )
  return toDashboardUser(data.user)
}

export async function resetUserPassword(id: string, password: string): Promise<DashboardUser> {
  if (!password.trim()) throw new Error("Password is required.")
  const passwordHash = await hashPassword(password)
  const user = await findUserById(id)
  if (!user) throw new Error("User not found.")
  return updateOwnAccount({ id, username: user.username, passwordHash, passwordResetRequired: false })
}

export async function updateUserStatus(id: string, status: UserStatus): Promise<DashboardUser> {
  const data = await postJson<{ user: any }>(
    `/auth/internal/user/${encodeURIComponent(id)}/account`,
    SERVICE_USER,
    { status },
    "PATCH",
  )
  return toDashboardUser(data.user)
}

export async function disableUser(id: string): Promise<DashboardUser> {
  try {
    await postJson<{ ok: boolean }>(
      `/settings/api/users/${encodeURIComponent(id)}/disable`,
      SERVICE_USER,
      {},
    )
  } catch (err: any) {
    throw new Error(err.message || "Failed to disable user.")
  }
  const user = await findUserById(id)
  if (!user) throw new Error("User not found.")
  return user
}

export async function updateUserRole(
  id: string,
  role: UserRole,
  actor: DashboardUser
): Promise<DashboardUser> {
  try {
    await postJson<{ ok: boolean }>(
      `/settings/api/users/${encodeURIComponent(id)}/role`,
      { id: actor.id, role: actor.role, roleId: actor.roleId },
      { role },
      "PATCH",
    )
  } catch (err: any) {
    throw new Error(err.message || "Failed to update role.")
  }
  const user = await findUserById(id)
  if (!user) throw new Error("User not found.")
  return user
}

export async function migrateSingleUserConfig(input: {
  username: string
  email?: string | null
  password: string
}): Promise<DashboardUser | null> {
  const username = input.username.trim()
  if (!username || !input.password.trim()) return null

  const passwordHash = await hashPassword(input.password)
  try {
    const data = await postJson<{ user: any | null }>("/auth/internal/migrate", SERVICE_USER, {
      username,
      email: input.email ?? "",
      passwordHash,
    })
    return data.user ? toDashboardUser(data.user) : null
  } catch {
    return null
  }
}

// Test helper — no longer needed for production
export async function createUserWithEmailForTest(input: {
  username: string
  email: string
  role: UserRole
}): Promise<DashboardUser> {
  const { randomBytes } = await import("crypto")
  const password = randomBytes(16).toString("hex")
  const data = await postJson<{ user: any; ok: boolean }>("/settings/api/users", SERVICE_USER, {
    username: input.username.trim(),
    email: input.email,
    password,
    role: input.role,
  })
  return toDashboardUser(data.user)
}
