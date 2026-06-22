"use client"

import { useEffect, useState } from "react"
import { apiClient } from "../api-client.ts"

export interface AuditStreamSettings {
  enabled: boolean
  targetType: "webhook" | "splunk_hec" | "syslog" | null
  endpointUrl: string | null
  authTokenSet: boolean
  lastEventId: number
  lastSuccessAt: string | null
  lastError: string | null
  updatedAt: string | null
}

let cached: AuditStreamSettings | null = null
let cacheTimestamp = 0
const CACHE_TTL_MS = 30_000

export async function fetchAuditStreamSettings(): Promise<AuditStreamSettings | null> {
  const now = Date.now()
  if (cached && now - cacheTimestamp < CACHE_TTL_MS) return cached
  try {
    const data = await apiClient<AuditStreamSettings>("/api/v1/settings/audit/stream")
    cached = data; cacheTimestamp = Date.now()
    return data
  } catch {
    return null
  }
}

export async function saveAuditStreamSettings(patch: Partial<{
  enabled: boolean
  targetType: "webhook" | "splunk_hec" | "syslog" | null
  endpointUrl: string | null
  authToken: string
}>): Promise<AuditStreamSettings> {
  const data = await apiClient<AuditStreamSettings>("/api/v1/settings/audit/stream", { method: "PATCH", body: patch })
  cached = data; cacheTimestamp = Date.now()
  return data
}

export async function testAuditStream(): Promise<{ ok: boolean; error?: string }> {
  return apiClient<{ ok: boolean; error?: string }>("/api/v1/settings/audit/stream/test", { method: "POST" })
}

export function useAuditStreamSettings(): {
  data: AuditStreamSettings | null
  isLoading: boolean
  mutate: (next?: AuditStreamSettings) => void
} {
  const [data, setData] = useState<AuditStreamSettings | null>(cached)
  const [isLoading, setIsLoading] = useState(cached == null)

  useEffect(() => {
    let alive = true
    fetchAuditStreamSettings().then((d) => {
      if (!alive) return
      setData(d); setIsLoading(false)
    })
    return () => { alive = false }
  }, [])

  const mutate = (next?: AuditStreamSettings) => {
    if (next) {
      cached = next; cacheTimestamp = Date.now(); setData(next)
    } else {
      cached = null; cacheTimestamp = 0
      fetchAuditStreamSettings().then(setData)
    }
  }

  return { data, isLoading, mutate }
}
