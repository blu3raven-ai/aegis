"use client"

import { useEffect, useState } from "react"

import { useSaveBarSection } from "@/app/(app)/settings/save-bar/SaveBarProvider"
import { Select } from "@/components/ui/Select"
import { SettingsCard } from "@/components/settings/SettingsCard"
import { SettingsRow } from "@/components/settings/SettingsRow"
import { SettingsSection } from "@/components/settings/SettingsSection"
import {
  saveProfile,
  useProfileSettings,
  type ProfileSettings,
} from "@/lib/client/settings/use-profile-settings"

const TIME_ZONES = [
  "Asia/Kuala_Lumpur",
  "Asia/Singapore",
  "Asia/Tokyo",
  "America/Los_Angeles",
  "America/New_York",
  "Europe/London",
  "Europe/Berlin",
  "Pacific/Auckland",
  "UTC",
]

const THEMES = [
  { value: "system", label: "System" },
  { value: "dark", label: "Dark" },
  { value: "light", label: "Light" },
] as const

type ThemeValue = (typeof THEMES)[number]["value"]

/**
 * Profile renders personal *preferences only*. Identity (avatar, username,
 * email) lives on AccountContent under Security & sessions so the same edit
 * flow isn't duplicated.
 */
export function ProfileSection() {
  const { data, mutate } = useProfileSettings()
  const [draft, setDraft] = useState<ProfileSettings | null>(data)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    if (data) setDraft(data)
  }, [data])

  const isDirty =
    !!data && !!draft && (draft.theme !== data.theme || draft.timezone !== data.timezone)
  const changeCount =
    data && draft
      ? Number(draft.theme !== data.theme) + Number(draft.timezone !== data.timezone)
      : 0

  const handleSave = async () => {
    if (!draft) return
    setSaving(true)
    setError(null)
    try {
      const next = await saveProfile(draft)
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
    id: "profile",
    dirty: isDirty,
    saving,
    count: changeCount,
    error,
    onSave: handleSave,
    onDiscard: handleDiscard,
  })

  const currentTz = draft?.timezone ?? ""
  // Surface the persisted zone in the dropdown even if it isn't in the curated
  // list — admins shouldn't lose their actual locale.
  const zoneOptions = currentTz && !TIME_ZONES.includes(currentTz)
    ? [currentTz, ...TIME_ZONES]
    : TIME_ZONES

  return (
    <SettingsSection
      id="profile"
      title="Profile"
      subtitle="Your personal preferences. Identity is managed under Security & Sessions."
    >
      <SettingsCard>
        <SettingsRow
          label="Time zone"
          description="Used for digests, audit-log timestamps, and SLA cut-offs"
        >
          <Select
            size="sm"
            aria-label="Time zone"
            value={currentTz}
            onChange={(e) => setDraft((d) => (d ? { ...d, timezone: e.target.value } : d))}
            disabled={!draft}
          >
            {zoneOptions.map((tz) => (
              <option key={tz} value={tz}>
                {tz}
              </option>
            ))}
          </Select>
        </SettingsRow>
        <SettingsRow label="Theme" description="Affects this device only">
          <Select
            size="sm"
            aria-label="Theme"
            value={draft?.theme ?? "system"}
            onChange={(e) => setDraft((d) => (d ? { ...d, theme: e.target.value as ThemeValue } : d))}
            disabled={!draft}
          >
            {THEMES.map((t) => (
              <option key={t.value} value={t.value}>
                {t.label}
              </option>
            ))}
          </Select>
        </SettingsRow>
      </SettingsCard>
    </SettingsSection>
  )
}
