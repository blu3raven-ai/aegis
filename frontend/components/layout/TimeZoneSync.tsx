"use client"

import { useProfileSettings } from "@/lib/client/settings/use-profile-settings"
import { setActiveTimeZone } from "@/lib/client/active-timezone"

/**
 * Mirrors the account "Time zone" preference into the module-level active zone
 * so every shared date formatter renders in it. Renders nothing.
 *
 * The sync happens during render (not in an effect) so formatters committed in
 * the same pass already use the right zone — an effect would apply a paint too
 * late and flash the previous zone. Setting a module global here is idempotent
 * and safe to repeat. A changed preference applies to a page the next time it
 * renders (i.e. on navigation), which for a rarely-changed setting is expected.
 */
export function TimeZoneSync() {
  const { data } = useProfileSettings()
  if (data?.timezone) setActiveTimeZone(data.timezone)
  return null
}
