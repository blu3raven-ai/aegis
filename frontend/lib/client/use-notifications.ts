"use client"

import { useEffect, useState, useCallback } from "react"
import { fetchUnreadCount } from "@/lib/client/notifications-api"
import { useSSE } from "@/components/providers/SSEProvider"

const REFRESH_EVENT = "notifications:refresh-count"

/** Trigger a bell count re-fetch from anywhere in the app. */
export function refreshNotificationCount() {
  window.dispatchEvent(new Event(REFRESH_EVENT))
}

export function useNotificationCount() {
  const [count, setCount] = useState(0)

  const refresh = useCallback(async () => {
    const c = await fetchUnreadCount()
    setCount(c)
  }, [])

  // Initial load
  useEffect(() => {
    void refresh()
  }, [refresh])

  // Re-fetch when another component signals a change (e.g., mark-all-read)
  useEffect(() => {
    const handler = () => void refresh()
    window.addEventListener(REFRESH_EVENT, handler)
    return () => window.removeEventListener(REFRESH_EVENT, handler)
  }, [refresh])

  // Real-time: increment count when new notification arrives via SSE
  useSSE("notification.new", () => {
    setCount((prev) => prev + 1)
  })

  return { count, refresh }
}
