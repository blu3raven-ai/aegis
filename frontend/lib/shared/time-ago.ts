import { getActiveTimeZone } from "@/lib/client/active-timezone"

export function timeAgo(iso: string): string {
  if (!iso) return ""
  const diff = Date.now() - new Date(iso).getTime()
  const minutes = Math.floor(diff / 60_000)
  if (minutes < 1) return "just now"
  if (minutes < 60) return `${minutes}m ago`
  const hours = Math.floor(minutes / 60)
  if (hours < 24) return `${hours}h ago`
  const days = Math.floor(hours / 24)
  if (days === 1) return "yesterday"
  if (days < 30) return `${days}d ago`
  return new Date(iso).toLocaleDateString(undefined, { timeZone: getActiveTimeZone() })
}

/** Relative label for a future timestamp, e.g. "in 6h" or "in 3d". */
export function timeUntil(iso: string): string {
  if (!iso) return ""
  const diff = new Date(iso).getTime() - Date.now()
  if (diff <= 0) return "due now"
  const minutes = Math.floor(diff / 60_000)
  if (minutes < 1) return "due now"
  if (minutes < 60) return `in ${minutes}m`
  const hours = Math.floor(minutes / 60)
  if (hours < 24) return `in ${hours}h`
  const days = Math.floor(hours / 24)
  if (days === 1) return "tomorrow"
  if (days < 30) return `in ${days}d`
  return new Date(iso).toLocaleDateString(undefined, { timeZone: getActiveTimeZone() })
}
