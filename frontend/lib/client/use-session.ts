"use client"

import { useEffect, useState } from "react"
import { apiClient } from "./api-client.ts"

export interface SessionUser {
  id: string
  username: string | null
  email: string
  role: string | null
  roleId: string | null
  status: string
}

interface MeResponse {
  user: SessionUser
}

export function useSession(): { user: SessionUser | null; loading: boolean } {
  const [user, setUser] = useState<SessionUser | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    apiClient<MeResponse>("/api/v1/auth/me", { suppressUnauthorizedRedirect: true })
      .then((res) => setUser(res.user))
      .catch(() => setUser(null))
      .finally(() => setLoading(false))
  }, [])

  return { user, loading }
}
