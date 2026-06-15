"use client"

import { useEffect, useState } from "react"
import { apiClient } from "../api-client.ts"

export interface ProfileSettings {
  theme: "system" | "dark" | "light"
  timezone: string
}

const DEFAULTS: ProfileSettings = { theme: "system", timezone: "UTC" }

let cached: ProfileSettings | null = null
let cacheTimestamp = 0
const CACHE_TTL_MS = 60_000

export async function fetchProfile(): Promise<ProfileSettings> {
  const now = Date.now()
  if (cached && now - cacheTimestamp < CACHE_TTL_MS) return cached
  try {
    const data = await apiClient<ProfileSettings>("/api/v1/settings/profile")
    cached = data
    cacheTimestamp = Date.now()
    return data
  } catch {
    return DEFAULTS
  }
}

export async function saveProfile(patch: Partial<ProfileSettings>): Promise<ProfileSettings> {
  const data = await apiClient<ProfileSettings>("/api/v1/settings/profile", {
    method: "PATCH",
    body: patch,
  })
  cached = data
  cacheTimestamp = Date.now()
  return data
}

export function invalidateProfileCache() {
  cacheTimestamp = 0
  cached = null
}

export function useProfileSettings(): {
  data: ProfileSettings | null
  isLoading: boolean
  mutate: (next?: ProfileSettings) => void
} {
  const [data, setData] = useState<ProfileSettings | null>(cached)
  const [isLoading, setIsLoading] = useState(cached == null)

  useEffect(() => {
    let alive = true
    fetchProfile().then((d) => {
      if (!alive) return
      setData(d)
      setIsLoading(false)
    })
    return () => {
      alive = false
    }
  }, [])

  const mutate = (next?: ProfileSettings) => {
    if (next) {
      cached = next
      cacheTimestamp = Date.now()
      setData(next)
    } else {
      invalidateProfileCache()
      fetchProfile().then(setData)
    }
  }

  return { data, isLoading, mutate }
}
