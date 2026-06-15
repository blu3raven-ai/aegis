"use client"

import { useEffect, useState } from "react"

import { useSaveBarSection } from "@/app/(app)/settings/save-bar/SaveBarProvider"
import { SettingsCard } from "@/components/settings/SettingsCard"
import { SettingsRow } from "@/components/settings/SettingsRow"
import { SettingsSection } from "@/components/settings/SettingsSection"
import { ToggleSwitch } from "@/components/settings/ToggleSwitch"
import {
  saveNotifications,
  useNotificationSettings,
  type NotificationSettings,
} from "@/lib/client/settings/use-notification-settings"

interface PrefDef {
  key: keyof NotificationSettings
  label: string
  trigger: string
  channel: string
}

const PREFS: PrefDef[] = [
  { key: "assignments", label: "Assignments", trigger: "When someone assigns you a finding", channel: "In-app + email" },
  { key: "mentions", label: "Mentions", trigger: "When you're @-mentioned in a comment", channel: "In-app + Slack DM" },
  { key: "kev", label: "KEV updates on your repos", trigger: "When CISA flags a CVE that affects code you work on", channel: "In-app only" },
  { key: "weeklyDigest", label: "Weekly digest", trigger: "Monday 9am · what changed this week", channel: "Email" },
  { key: "marketing", label: "Marketing & product updates", trigger: "Major releases · roughly monthly", channel: "Email only" },
]

export function NotificationsPreferencesSection() {
  const { data, mutate } = useNotificationSettings()
  const [draft, setDraft] = useState<NotificationSettings | null>(data)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    if (data) setDraft(data)
  }, [data])

  const isDirty = !!data && !!draft && PREFS.some(({ key }) => draft[key] !== data[key])
  const changeCount =
    data && draft ? PREFS.reduce((acc, { key }) => acc + (draft[key] !== data[key] ? 1 : 0), 0) : 0

  const handleSave = async () => {
    if (!draft) return
    setSaving(true)
    setError(null)
    try {
      const next = await saveNotifications(draft)
      mutate(next)
      setDraft(next)
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to save.")
    } finally {
      setSaving(false)
    }
  }

  const handleDiscard = () => {
    if (data) setDraft(data)
    setError(null)
  }

  useSaveBarSection({
    id: "notifications-preferences",
    dirty: isDirty,
    saving,
    count: changeCount,
    error,
    onSave: handleSave,
    onDiscard: handleDiscard,
  })

  return (
    <SettingsSection
      id="notifications"
      title="Notifications"
      subtitle="What you get pinged about. Affects the bell and the email digest."
    >
      <SettingsCard>
        {PREFS.map((pref) => (
          <SettingsRow
            key={pref.key}
            label={pref.label}
            description={pref.trigger}
          >
            <span className="text-xs text-[var(--color-text-tertiary)]">
              {pref.channel}
            </span>
            <ToggleSwitch
              label={`Toggle ${pref.label}`}
              checked={draft ? draft[pref.key] : false}
              onChange={(next) =>
                setDraft((d) => (d ? { ...d, [pref.key]: next } : d))
              }
            />
          </SettingsRow>
        ))}
      </SettingsCard>
    </SettingsSection>
  )
}
