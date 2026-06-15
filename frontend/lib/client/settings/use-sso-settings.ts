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

let cached: SsoSettings | null = null
let cacheTimestamp = 0
const CACHE_TTL_MS = 60_000

export async function fetchSsoSettings(): Promise<SsoSettings | null> {
  const now = Date.now()
  if (cached && now - cacheTimestamp < CACHE_TTL_MS) return cached
  try {
    const data = await apiClient<SsoSettings>("/api/v1/settings/sso")
    cached = data
    cacheTimestamp = Date.now()
    return data
  } catch {
    return null
  }
}

export async function saveSsoSettings(patch: Partial<{
  enabled: boolean
  protocol: "saml" | "oidc" | null
  defaultRoleId: string | null
  samlMetadataUrl: string | null
  samlMetadataXml: string | null
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
  mutate: (next?: SsoSettings) => void
} {
  const [data, setData] = useState<SsoSettings | null>(cached)
  const [isLoading, setIsLoading] = useState(cached == null)

  useEffect(() => {
    let alive = true
    fetchSsoSettings().then((d) => {
      if (!alive) return
      setData(d)
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
    } else {
      cached = null
      cacheTimestamp = 0
      fetchSsoSettings().then(setData)
    }
  }

  return { data, isLoading, mutate }
}
