"use client"

import { useEffect, useState } from "react"
import { apiClient } from "../api-client.ts"
import { invalidateBrandingCache } from "../branding/client"

export interface OrgSettings {
  name: string | null
  logoDataUrl: string | null
  updatedAt: string | null
}

const DEFAULTS: OrgSettings = {
  name: null,
  logoDataUrl: null,
  updatedAt: null,
}

let cached: OrgSettings | null = null
let cacheTimestamp = 0
const CACHE_TTL_MS = 60_000

export async function fetchOrgSettings(): Promise<OrgSettings> {
  const now = Date.now()
  if (cached && now - cacheTimestamp < CACHE_TTL_MS) return cached
  try {
    const data = await apiClient<OrgSettings>("/api/v1/settings/org")
    cached = data
    cacheTimestamp = Date.now()
    return data
  } catch {
    return DEFAULTS
  }
}

export async function saveOrgSettings(
  patch: Partial<Omit<OrgSettings, "updatedAt" | "logoDataUrl">>,
): Promise<OrgSettings> {
  const data = await apiClient<OrgSettings>("/api/v1/settings/org", {
    method: "PATCH",
    body: patch,
  })
  cached = data
  cacheTimestamp = Date.now()
  invalidateBrandingCache()
  return data
}

export async function setOrgLogo(dataUrl: string): Promise<OrgSettings> {
  const data = await apiClient<OrgSettings>("/api/v1/settings/org/logo", {
    method: "POST",
    body: { dataUrl },
  })
  cached = data
  cacheTimestamp = Date.now()
  invalidateBrandingCache()
  return data
}

export async function clearOrgLogo(): Promise<OrgSettings> {
  const data = await apiClient<OrgSettings>("/api/v1/settings/org/logo", {
    method: "DELETE",
  })
  cached = data
  cacheTimestamp = Date.now()
  invalidateBrandingCache()
  return data
}

export function useOrgSettings(): {
  data: OrgSettings | null
  isLoading: boolean
  mutate: (next?: OrgSettings) => void
} {
  const [data, setData] = useState<OrgSettings | null>(cached)
  const [isLoading, setIsLoading] = useState(cached == null)

  useEffect(() => {
    let alive = true
    fetchOrgSettings().then((d) => {
      if (!alive) return
      setData(d)
      setIsLoading(false)
    })
    return () => {
      alive = false
    }
  }, [])

  const mutate = (next?: OrgSettings) => {
    if (next) {
      cached = next
      cacheTimestamp = Date.now()
      setData(next)
    } else {
      cached = null
      cacheTimestamp = 0
      fetchOrgSettings().then(setData)
    }
  }

  return { data, isLoading, mutate }
}
