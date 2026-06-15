import { apiClient } from "./api-client.ts"

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
    return await apiClient<{ notifications: Notification[]; total: number }>(
      `/api/v1/notifications/list${qs ? `?${qs}` : ""}`,
    )
  } catch {
    return { notifications: [], total: 0 }
  }
}

export async function fetchUnreadCount(): Promise<number> {
  try {
    const data = await apiClient<{ count?: number }>("/api/v1/notifications/unread-count")
    return data.count ?? 0
  } catch {
    return 0
  }
}

export async function markNotificationRead(notificationId?: string): Promise<void> {
  await apiClient("/api/v1/notifications/mark-read", {
    method: "POST",
    body: { notification_id: notificationId ?? null },
  }).catch(() => {})
}

export async function deleteNotification(notificationId: string): Promise<void> {
  await apiClient(`/api/v1/notifications/${notificationId}`, { method: "DELETE" }).catch(() => {})
}
