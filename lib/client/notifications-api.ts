export interface Notification {
  id: string
  type: string
  category: string
  severity: "info" | "warning" | "error"
  title: string
  message: string
  context: Record<string, string>
  link: string | null
  createdAt: string
  readAt: string | null
}

export async function fetchNotifications(opts?: {
  unreadOnly?: boolean
  limit?: number
  offset?: number
}): Promise<{ notifications: Notification[]; total: number }> {
  const params = new URLSearchParams()
  if (opts?.unreadOnly) params.set("unread_only", "true")
  if (opts?.limit) params.set("limit", String(opts.limit))
  if (opts?.offset) params.set("offset", String(opts.offset))
  const qs = params.toString()
  try {
    const res = await fetch(`/api/notifications/list${qs ? `?${qs}` : ""}`, { cache: "no-store" })
    if (!res.ok) return { notifications: [], total: 0 }
    return await res.json()
  } catch {
    return { notifications: [], total: 0 }
  }
}

export async function fetchUnreadCount(): Promise<number> {
  try {
    const res = await fetch("/api/notifications/unread-count", { cache: "no-store" })
    if (!res.ok) return 0
    const data = await res.json()
    return data.count ?? 0
  } catch {
    return 0
  }
}

export async function markNotificationRead(notificationId?: string): Promise<void> {
  await fetch("/api/notifications/mark-read", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ notification_id: notificationId ?? null }),
  })
}

export async function deleteNotification(notificationId: string): Promise<void> {
  await fetch(`/api/notifications/${notificationId}`, { method: "DELETE" })
}
