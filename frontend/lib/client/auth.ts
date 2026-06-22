import { useEffect, useState } from "react"
import type { UserRole } from "@/lib/shared/auth/roles.ts"
import { apiClient } from "./api-client.ts"

export interface CurrentUser {
  id: string
  username: string
  email?: string | null
  role: UserRole
  status: "active" | "disabled" | "pending"
  totpEnabled: boolean
  avatarUrl?: string | null
}

export async function fetchCurrentUser(): Promise<CurrentUser | null> {
  try {
    const payload = await apiClient<{ user?: CurrentUser | null }>("/api/v1/auth/me")
    return payload.user ?? null
  } catch {
    return null
  }
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
