import "server-only"

import { cookies } from "next/headers"
import { encryptMfaSession, decryptMfaSession } from "@/lib/server/session-token"

const MFA_COOKIE_NAME = "__mfa_pending"
const MFA_DURATION_S = 5 * 60

export async function createMfaSession(userId: string): Promise<void> {
  const payload = {
    userId,
    exp: Math.floor(Date.now() / 1000) + MFA_DURATION_S,
    purpose: "mfa_pending" as const,
  }
  const token = encryptMfaSession(payload)
  const cookieStore = await cookies()
  cookieStore.set(MFA_COOKIE_NAME, token, {
    httpOnly: true,
    sameSite: "strict",
    path: "/",
    maxAge: MFA_DURATION_S,
    secure: process.env.NODE_ENV === "production",
  })
}

export async function getMfaSession(): Promise<{ userId: string } | null> {
  const cookieStore = await cookies()
  const token = cookieStore.get(MFA_COOKIE_NAME)?.value
  if (!token) return null
  const payload = decryptMfaSession(token)
  if (!payload) return null
  return { userId: payload.userId }
}

export async function clearMfaSession(): Promise<void> {
  const cookieStore = await cookies()
  cookieStore.set(MFA_COOKIE_NAME, "", {
    maxAge: 0,
    path: "/",
    httpOnly: true,
    sameSite: "strict",
    secure: process.env.NODE_ENV === "production",
  })
}
