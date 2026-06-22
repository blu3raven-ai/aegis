"use client"

import { useEffect, useState } from "react"
import { apiClient } from "../api-client.ts"

export type RecoveryCodePolicy = "mandatory" | "optional" | "disabled"

export interface AuthSecuritySettings {
  requireMfaManualUsers: boolean
  requireMfaAdmins: boolean
  trustedSessionDurationDays: number
  recoveryCodePolicy: RecoveryCodePolicy
}

const CSRF_COOKIE_NAME = "__Host-csrf"

function readCsrfCookie(): string | null {
  if (typeof document === "undefined") return null
  for (const pair of document.cookie.split(";").map((p) => p.trim())) {
    const [k, ...rest] = pair.split("=")
    if (k === CSRF_COOKIE_NAME) return rest.join("=")
  }
  return null
}

export class GqlError extends Error {
  code: string | null
  constructor(message: string, code: string | null) {
    super(message)
    this.code = code
  }
}

async function gqlFetch<T>(
  operationName: string,
  query: string,
  variables: Record<string, unknown>,
): Promise<T> {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    Accept: "application/json",
  }
  const csrf = readCsrfCookie()
  if (csrf !== null) headers["X-CSRF-Token"] = csrf

  const res = await fetch("/api/v1/graphql", {
    method: "POST",
    headers,
    body: JSON.stringify({ operationName, query, variables }),
    credentials: "include",
  })
  const body = (await res.json()) as {
    data?: T
    errors?: { message: string; extensions?: { code?: string } }[]
  }
  if (body.errors && body.errors.length > 0) {
    const first = body.errors[0]
    throw new GqlError(first.message, first.extensions?.code ?? null)
  }
  if (!body.data) {
    throw new GqlError(`${operationName} returned no data`, null)
  }
  return body.data
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
