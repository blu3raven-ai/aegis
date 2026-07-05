"use client"

import { useEffect, useState } from "react"
import { apiClient } from "../api-client.ts"

export interface SsoSettings {
  enabled: boolean
  protocol: "saml" | "oidc" | null
  defaultRoleId: string | null
  samlMetadataUrl: string | null
  samlMetadataXml: string | null
  samlSpCertificate: string | null
  samlSpPrivateKeySet: boolean
  samlValidateMetadataSignature: boolean
  samlAcsUrl: string
  samlSpEntityId: string
  samlSpMetadataUrl: string
  oidcDiscoveryUrl: string | null
  oidcClientId: string | null
  oidcClientSecretSet: boolean
  oidcScopes: string
  oidcRedirectUri: string
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

const SSO_SETTINGS_QUERY = `query SsoSettings {
  settings {
    sso {
      enabled
      protocol
      defaultRoleId
      samlMetadataUrl
      samlMetadataXml
      samlSpCertificate
      samlSpPrivateKeySet
      samlValidateMetadataSignature
      samlAcsUrl
      samlSpEntityId
      samlSpMetadataUrl
      oidcDiscoveryUrl
      oidcClientId
      oidcClientSecretSet
      oidcScopes
      oidcRedirectUri
      updatedAt
    }
  }
}`

let cached: SsoSettings | null = null
let cacheTimestamp = 0
const CACHE_TTL_MS = 60_000

export async function fetchSsoSettings(): Promise<SsoSettings> {
  const now = Date.now()
  if (cached && now - cacheTimestamp < CACHE_TTL_MS) return cached
  const data = await gqlFetch<{ settings: { sso: SsoSettings } }>(
    "SsoSettings",
    SSO_SETTINGS_QUERY,
    {},
  )
  cached = data.settings.sso
  cacheTimestamp = Date.now()
  return cached
}

export async function saveSsoSettings(patch: Partial<{
  enabled: boolean
  protocol: "saml" | "oidc" | null
  defaultRoleId: string | null
  samlMetadataUrl: string | null
  samlMetadataXml: string | null
  samlValidateMetadataSignature: boolean
  oidcDiscoveryUrl: string | null
  oidcClientId: string | null
  oidcClientSecret: string
  oidcScopes: string
}>): Promise<SsoSettings> {
  const data = await apiClient<SsoSettings>("/api/v1/settings/sso", {
    method: "PATCH",
    body: patch,
  })
  cached = data
  cacheTimestamp = Date.now()
  return data
}

export async function generateSamlKeypair(): Promise<{ certificate: string; updatedAt: string }> {
  const data = await apiClient<{ certificate: string; updatedAt: string }>(
    "/api/v1/settings/sso/saml/sp-keypair", { method: "POST" },
  )
  // bust cache so next fetch reflects the new certificate
  cached = null
  return data
}

export async function refreshSamlMetadata(): Promise<{ ok: boolean; error?: string }> {
  const data = await apiClient<{ ok: boolean; error?: string }>(
    "/api/v1/settings/sso/saml/refresh-metadata", { method: "POST" },
  )
  // bust cache so next fetch reflects the refreshed metadata
  cached = null
  return data
}

export function useSsoSettings(): {
  data: SsoSettings | null
  isLoading: boolean
  error: GqlError | null
  mutate: (next?: SsoSettings) => void
} {
  const [data, setData] = useState<SsoSettings | null>(cached)
  const [isLoading, setIsLoading] = useState(cached == null)
  const [error, setError] = useState<GqlError | null>(null)

  useEffect(() => {
    let alive = true
    fetchSsoSettings()
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

  const mutate = (next?: SsoSettings) => {
    if (next) {
      cached = next
      cacheTimestamp = Date.now()
      setData(next)
      setError(null)
    } else {
      cached = null
      cacheTimestamp = 0
      fetchSsoSettings()
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
