"use client"

import { createContext, useContext, useEffect, useState, type ReactNode } from "react"
import type { LicenseStatus } from "@/lib/shared/license/types"
import { apiClient } from "../api-client.ts"

const DEFAULT_STATUS: LicenseStatus = {
  tier: "community",
  addons: [],
  limits: {
    max_users: 10,
    max_remote_runners: 0,
    max_source_connections: 2,
    custom_roles: false,
    teams: false,
    insights_tab: false,
    health_tab: false,
    ai_review: false,
    custom_scan_schedule: false,
    sso: false,
    audit_log: false,
    data_retention_days: 90,
  },
  usage: {
    users: 0,
    source_connections: 0,
    teams: 0,
    custom_roles: 0,
    remote_runners: 0,
  },
  license: null,
}


let cachedStatus: LicenseStatus = DEFAULT_STATUS
let cacheTimestamp = 0
const CACHE_TTL_MS = 60_000 // 1 minute

export async function fetchLicenseStatus(): Promise<LicenseStatus> {
  const now = Date.now()
  if (cacheTimestamp > 0 && now - cacheTimestamp < CACHE_TTL_MS) {
    return cachedStatus
  }
  try {
    const data = await apiClient<LicenseStatus>("/api/v1/license/status")
    cachedStatus = data
    cacheTimestamp = Date.now()
    return data
  } catch {
    return DEFAULT_STATUS
  }
}

/** Invalidate the cache so the next useLicense() call refetches. */
export function invalidateLicenseCache() {
  cacheTimestamp = 0
}

const LicenseContext = createContext<(LicenseStatus & { isLoading: boolean }) | null>(null)

export function LicenseProvider({ children }: { children: ReactNode }) {
  const [status, setStatus] = useState<LicenseStatus>(cachedStatus)
  const [isLoading, setIsLoading] = useState(cacheTimestamp === 0)

  useEffect(() => {
    fetchLicenseStatus().then((s) => {
      setStatus(s)
      setIsLoading(false)
    })
  }, [])

  return (
    <LicenseContext.Provider value={{ ...status, isLoading }}>
      {children}
    </LicenseContext.Provider>
  )
}

export function useLicense() {
  const ctx = useContext(LicenseContext)
  const hasProvider = ctx !== null

  // Always call hooks (Rules of Hooks) — ignored when provider is present
  const [status, setStatus] = useState<LicenseStatus>(cachedStatus)
  const [isLoading, setIsLoading] = useState(cacheTimestamp === 0)

  useEffect(() => {
    if (hasProvider) return
    fetchLicenseStatus().then((s) => {
      setStatus(s)
      setIsLoading(false)
    })
  }, [hasProvider])

  if (ctx) return ctx
  return { ...status, isLoading }
}
