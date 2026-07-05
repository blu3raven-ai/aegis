"use client"

import { useEffect, useState } from "react"

import { SettingsCard } from "@/components/settings/SettingsCard"
import { SettingsRow } from "@/components/settings/SettingsRow"
import { ToggleSwitch } from "@/components/settings/ToggleSwitch"
import { useSaveBarSection } from "@/app/(app)/settings/save-bar/SaveBarProvider"
import {
  saveNotifications,
  useNotificationSettings,
  type NotificationSettings,
} from "@/lib/client/settings/use-notification-settings"
import type { DetailComponentProps } from "../registry"

interface PrefDef {
  key: keyof NotificationSettings
  label: string
  description: string
}

// The three toggles below are wired to real in-app notifications.
const LIVE_PREFS: PrefDef[] = [
  { key: "assignments", label: "Assignments", description: "When someone assigns you a finding" },
  { key: "mentions", label: "Mentions", description: "When you're @-mentioned in a comment" },
  { key: "kev", label: "KEV updates on your repos", description: "When CISA flags a CVE that affects code you work on" },
]

// Not built yet — rendered as a disabled preview pinned off.
const COMING_SOON_PREFS: { label: string; description: string }[] = [
  { label: "Weekly digest", description: "A weekly summary of what changed" },
  { label: "Product updates", description: "New features and major releases" },
]

export function NotificationsDetail(_: DetailComponentProps) {
  const { data, mutate } = useNotificationSettings()
  const [draft, setDraft] = useState<NotificationSettings | null>(data)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    if (data) setDraft(data)
  }, [data])

  const changedKeys = data && draft ? LIVE_PREFS.filter(({ key }) => draft[key] !== data[key]) : []
  const isDirty = changedKeys.length > 0

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
    id: "notifications",
    dirty: isDirty,
    saving,
    count: changedKeys.length,
    error,
    onSave: handleSave,
    onDiscard: handleDiscard,
  })

  return (
    <div className="flex flex-col gap-4">
      <SettingsCard>
        {LIVE_PREFS.map((pref) => (
          <SettingsRow key={pref.key} label={pref.label} description={pref.description}>
            <ToggleSwitch
              label={`Toggle ${pref.label}`}
              checked={draft ? draft[pref.key] : false}
              onChange={(next) =>
                setDraft((d) => (d ? { ...d, [pref.key]: next } : d))
              }
            />
          </SettingsRow>
        ))}
        {COMING_SOON_PREFS.map((pref) => (
          <SettingsRow
            key={pref.label}
            label={pref.label}
            description={pref.description}
          >
            <span className="rounded-full border border-[var(--color-border)] px-2 py-0.5 text-2xs font-medium text-[var(--color-text-tertiary)]">
              Coming soon
            </span>
            <ToggleSwitch
              label={`Toggle ${pref.label}`}
              checked={false}
              onChange={() => {}}
              disabled
            />
          </SettingsRow>
        ))}
      </SettingsCard>
    </div>
  )
}
