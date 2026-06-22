"use client"

import { useEffect, useState } from "react"
import { apiClient } from "../api-client.ts"

export interface ScimSettings {
  enabled: boolean
  defaultRoleId: string | null
  tokenSet: boolean
  scimEndpointUrl: string
  updatedAt: string | null
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

const SCIM_SETTINGS_QUERY = `query ScimSettings {
  settings {
    scim {
      enabled
      defaultRoleId
      tokenSet
      scimEndpointUrl
      updatedAt
    }
  }
}`

let cached: ScimSettings | null = null
let cacheTimestamp = 0
const CACHE_TTL_MS = 60_000

export async function fetchScimSettings(): Promise<ScimSettings> {
  const now = Date.now()
  if (cached && now - cacheTimestamp < CACHE_TTL_MS) return cached
  const data = await gqlFetch<{ settings: { scim: ScimSettings } }>(
    "ScimSettings",
    SCIM_SETTINGS_QUERY,
    {},
  )
  cached = data.settings.scim
  cacheTimestamp = Date.now()
  return cached
}

export async function saveScimSettings(
  patch: Partial<{ enabled: boolean; defaultRoleId: string | null }>,
): Promise<ScimSettings> {
  const data = await apiClient<ScimSettings>("/api/v1/settings/scim", { method: "PATCH", body: patch })
  cached = data
  cacheTimestamp = Date.now()
  return data
}

export async function generateScimToken(): Promise<{ token: string; updatedAt: string }> {
  const data = await apiClient<{ token: string; updatedAt: string }>("/api/v1/settings/scim/token", {
    method: "POST",
  })
  // bust cache so next fetch reflects the new token state
  cached = null
  return data
}

export async function clearScimToken(): Promise<ScimSettings> {
  const data = await apiClient<ScimSettings>("/api/v1/settings/scim/token", { method: "DELETE" })
  cached = data
  cacheTimestamp = Date.now()
  return data
}

export function useScimSettings(): {
  data: ScimSettings | null
  isLoading: boolean
  error: GqlError | null
  mutate: (next?: ScimSettings) => void
} {
  const [data, setData] = useState<ScimSettings | null>(cached)
  const [isLoading, setIsLoading] = useState(cached == null)
  const [error, setError] = useState<GqlError | null>(null)

  useEffect(() => {
    let alive = true
    fetchScimSettings()
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

  const mutate = (next?: ScimSettings) => {
    if (next) {
      cached = next
      cacheTimestamp = Date.now()
      setData(next)
      setError(null)
    } else {
      cached = null
      cacheTimestamp = 0
      fetchScimSettings()
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
