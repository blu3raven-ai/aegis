import { useEffect, useState } from "react"
import type { UserRole } from "@/lib/shared/auth/roles.ts"

export interface CurrentUser {
  id: string
  username: string
  email?: string | null
  role: UserRole
  status: "active" | "disabled" | "pending"
  totpEnabled: boolean
  passwordResetRequired: boolean
  avatarUrl?: string | null
}

export async function fetchCurrentUser(): Promise<CurrentUser | null> {
  const response = await fetch("/api/me", { cache: "no-store" })
  if (!response.ok) return null
  const payload = await response.json() as { user?: CurrentUser | null }
  return payload.user ?? null
}

export function useCurrentUser() {
  const [user, setUser] = useState<CurrentUser | null>(null)
  const [isLoading, setIsLoading] = useState(true)

  useEffect(() => {
    fetchCurrentUser()
      .then(setUser)
      .finally(() => setIsLoading(false))
  }, [])

  return { user, isLoading }
}
