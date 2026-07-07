import { apiClient } from "./api-client.ts"
import { gqlFetch } from "./graphql-fetch.ts"
export interface Notification {
  id: string
  type: string
  category: string
  severity: "info" | "warning" | "error"
  title: string
  message: string
  context: Record<string, unknown>
  link: string | null
  createdAt: string
  readAt: string | null
}

const NOTIFICATIONS_INBOX_QUERY = `query NotificationsInbox($unreadOnly: Boolean, $limit: Int, $offset: Int) {
  notifications {
    inbox(unreadOnly: $unreadOnly, limit: $limit, offset: $offset) {
      notifications { id type category severity title message context link createdAt read }
      total
    }
  }
}`

const NOTIFICATIONS_UNREAD_COUNT_QUERY = `query NotificationsUnreadCount {
  notifications { unreadCount }
}`

interface GqlInboxNotification {
  id: string
  type: string
  category: string
  severity: string
  title: string
  message: string
  context: Record<string, unknown>
  link: string | null
  createdAt: string
  read: boolean
}

export async function fetchNotifications(opts?: {
  unreadOnly?: boolean
  limit?: number
  offset?: number
}): Promise<{ notifications: Notification[]; total: number }> {
  try {
    const data = await gqlFetch<{
      notifications: { inbox: { notifications: GqlInboxNotification[]; total: number } }
    }>("NotificationsInbox", NOTIFICATIONS_INBOX_QUERY, {
      unreadOnly: opts?.unreadOnly ?? false,
      limit: opts?.limit,
      offset: opts?.offset,
    })

    const notifications: Notification[] = data.notifications.inbox.notifications.map((n) => ({
      id: n.id,
      type: n.type,
      category: n.category,
      severity: n.severity as Notification["severity"],
      title: n.title,
      message: n.message,
      context: n.context ?? {},
      link: n.link,
      createdAt: n.createdAt,
      readAt: n.read ? n.createdAt : null,
    }))

    return { notifications, total: data.notifications.inbox.total }
  } catch {
    return { notifications: [], total: 0 }
  }
}

export async function fetchUnreadCount(): Promise<number> {
  try {
    const data = await gqlFetch<{ notifications: { unreadCount: number } }>(
      "NotificationsUnreadCount",
      NOTIFICATIONS_UNREAD_COUNT_QUERY,
      {},
    )
    return data.notifications?.unreadCount ?? 0
  } catch {
    return 0
  }
}

export async function markNotificationRead(notificationId?: string): Promise<void> {
  await apiClient("/api/v1/notifications/inbox/mark-read", {
    method: "POST",
    body: { notification_id: notificationId ?? null },
  }).catch(() => {})
}

export async function deleteNotification(notificationId: string): Promise<void> {
  await apiClient(`/api/v1/notifications/inbox/${notificationId}`, {
    method: "DELETE",
  }).catch(() => {})
}
