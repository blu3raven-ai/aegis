"use client"

import { useEffect, useState } from "react"
import { gqlFetch, GqlError } from "../graphql-fetch.ts"
import { apiClient } from "../api-client.ts"

export type RecoveryCodePolicy = "mandatory" | "optional" | "disabled"

export interface AuthSecuritySettings {
  requireMfaManualUsers: boolean
  requireMfaAdmins: boolean
  trustedSessionDurationDays: number
  recoveryCodePolicy: RecoveryCodePolicy
}
const AUTH_SECURITY_QUERY = `query AuthSecuritySettings {
  settings {
    authSecurity {
      requireMfaManualUsers
      requireMfaAdmins
      trustedSessionDurationDays
      recoveryCodePolicy
    }
  }
}`

let cached: AuthSecuritySettings | null = null
let cacheTimestamp = 0
const CACHE_TTL_MS = 60_000

export async function fetchAuthSecurity(): Promise<AuthSecuritySettings> {
  const now = Date.now()
  if (cached && now - cacheTimestamp < CACHE_TTL_MS) return cached
  const data = await gqlFetch<{ settings: { authSecurity: AuthSecuritySettings } }>(
    "AuthSecuritySettings",
    AUTH_SECURITY_QUERY,
    {},
  )
  cached = data.settings.authSecurity
  cacheTimestamp = Date.now()
  return cached
}

export async function saveAuthSecurity(
  next: AuthSecuritySettings,
): Promise<AuthSecuritySettings> {
  await apiClient<{ ok: boolean }>("/api/v1/settings/auth-security", {
    method: "PATCH",
    body: next,
  })
  cached = next
  cacheTimestamp = Date.now()
  return next
}

export function useAuthSecurity(): {
  data: AuthSecuritySettings | null
  isLoading: boolean
  error: GqlError | null
  mutate: (next?: AuthSecuritySettings) => void
} {
  const [data, setData] = useState<AuthSecuritySettings | null>(cached)
  const [isLoading, setIsLoading] = useState(cached == null)
  const [error, setError] = useState<GqlError | null>(null)

  useEffect(() => {
    let alive = true
    fetchAuthSecurity()
      .then((d) => {
        if (!alive) return
        setData(d)
        setError(null)
        setIsLoading(false)
      })
      .catch((e: unknown) => {
        if (!alive) return
        setError(e instanceof GqlError ? e : new GqlError(String(e), null))
        setIsLoading(false)
      })
    return () => {
      alive = false
    }
  }, [])

  const mutate = (next?: AuthSecuritySettings) => {
    if (next) {
      cached = next
      cacheTimestamp = Date.now()
      setData(next)
      setError(null)
    } else {
      cached = null
      cacheTimestamp = 0
      fetchAuthSecurity()
        .then((d) => {
          setData(d)
          setError(null)
        })
        .catch((e: unknown) => {
          setError(e instanceof GqlError ? e : new GqlError(String(e), null))
        })
    }
  }

  return { data, isLoading, error, mutate }
}
