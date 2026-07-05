"use client"

import { useEffect, useState } from "react"
import { apiClient } from "../api-client.ts"

export interface NotificationSettings {
  assignments: boolean
  mentions: boolean
  kev: boolean
  weeklyDigest: boolean
  marketing: boolean
}

const DEFAULTS: NotificationSettings = {
  assignments: true,
  mentions: true,
  kev: true,
  weeklyDigest: true,
  marketing: false,
}

let cached: NotificationSettings | null = null
let cacheTimestamp = 0
const CACHE_TTL_MS = 60_000

export async function fetchNotifications(): Promise<NotificationSettings> {
  const now = Date.now()
  if (cached && now - cacheTimestamp < CACHE_TTL_MS) return cached
  try {
    const data = await apiClient<NotificationSettings>("/api/v1/settings/account/notification-prefs")
    cached = data
    cacheTimestamp = Date.now()
    return data
  } catch {
    return DEFAULTS
  }
}

export async function saveNotifications(patch: Partial<NotificationSettings>): Promise<NotificationSettings> {
  const data = await apiClient<NotificationSettings>("/api/v1/settings/account/notification-prefs", {
    method: "PATCH",
    body: {
      assignments: patch.assignments ?? null,
      mentions: patch.mentions ?? null,
      kev: patch.kev ?? null,
      weeklyDigest: patch.weeklyDigest ?? null,
      marketing: patch.marketing ?? null,
    },
  })
  cached = data
  cacheTimestamp = Date.now()
  return data
}

export function useNotificationSettings(): {
  data: NotificationSettings | null
  isLoading: boolean
  mutate: (next?: NotificationSettings) => void
} {
  const [data, setData] = useState<NotificationSettings | null>(cached)
  const [isLoading, setIsLoading] = useState(cached == null)

  useEffect(() => {
    let alive = true
    fetchNotifications().then((d) => {
      if (!alive) return
      setData(d)
      setIsLoading(false)
    })
    return () => {
      alive = false
    }
  }, [])

  const mutate = (next?: NotificationSettings) => {
    if (next) {
      cached = next
      cacheTimestamp = Date.now()
      setData(next)
    } else {
      cached = null
      cacheTimestamp = 0
      fetchNotifications().then(setData)
    }
  }

  return { data, isLoading, mutate }
}
