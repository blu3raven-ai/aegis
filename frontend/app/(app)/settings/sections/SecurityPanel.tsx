"use client"

import { useEffect, useState } from "react"

import { Select } from "@/components/ui/Select"
import { ActiveSessionsCard } from "@/components/settings/ActiveSessionsCard"
import { SettingsRow } from "@/components/settings/SettingsRow"
import { useSaveBarSection } from "@/app/(app)/settings/save-bar/SaveBarProvider"
import { saveProfile, useProfileSettings } from "@/lib/client/settings/use-profile-settings"
import {
  THEME_CHANGE_EVENT,
  getStoredTheme,
  setTheme,
  type ThemeChoice,
} from "@/lib/client/theme"
import { AccountContent } from "../account/AccountContent"
import type { DetailComponentProps } from "../registry"

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

const THEMES: { value: ThemeChoice; label: string }[] = [
  { value: "system", label: "System" },
  { value: "dark", label: "Dark" },
  { value: "light", label: "Light" },
]

/** Personal preferences rendered inside the Profile card.
 *
 *  Both rows report to the page save bar, so changing either surfaces the
 *  "unsaved changes" footer and nothing takes effect until Save. Time zone is a
 *  server-persisted account preference; theme is device-local (localStorage)
 *  and, once saved, applies live through the same mechanism as the header
 *  toggle — which is why its caption reads "Affects this device only". */
function PreferenceRows() {
  const { data, mutate } = useProfileSettings()
  const [timezone, setTimezone] = useState<string | null>(data?.timezone ?? null)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    if (data) setTimezone(data.timezone)
  }, [data])

  // Theme draft vs the theme currently applied to the app. Editing the draft
  // marks the save bar dirty; Save applies it, Discard reverts it. The header
  // toggle applies instantly, so mirror its changes into both here.
  const [theme, setThemeChoice] = useState<ThemeChoice>("system")
  const [appliedTheme, setAppliedTheme] = useState<ThemeChoice>("system")
  useEffect(() => {
    const current = getStoredTheme()
    setAppliedTheme(current)
    setThemeChoice(current)
    function onThemeChange(e: Event) {
      const next = (e as CustomEvent<{ theme: string }>).detail?.theme
      if (next === "dark" || next === "light" || next === "system") {
        setAppliedTheme(next)
        setThemeChoice(next)
      }
    }
    window.addEventListener(THEME_CHANGE_EVENT, onThemeChange)
    return () => window.removeEventListener(THEME_CHANGE_EVENT, onThemeChange)
  }, [])

  const tzDirty = !!data && timezone != null && timezone !== data.timezone
  const themeDirty = theme !== appliedTheme
  const isDirty = tzDirty || themeDirty
  const changeCount = Number(tzDirty) + Number(themeDirty)

  const handleSave = async () => {
    setSaving(true)
    setError(null)
    try {
      if (tzDirty && timezone != null) {
        const next = await saveProfile({ timezone })
        mutate(next)
        setTimezone(next.timezone)
      }
      if (themeDirty) {
        setTheme(theme)
        setAppliedTheme(theme)
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to save.")
    } finally {
      setSaving(false)
    }
  }

  const handleDiscard = () => {
    if (data) setTimezone(data.timezone)
    setThemeChoice(appliedTheme)
    setError(null)
  }

  useSaveBarSection({
    id: "preferences",
    dirty: isDirty,
    saving,
    count: changeCount,
    error,
    onSave: handleSave,
    onDiscard: handleDiscard,
  })

  const currentTz = timezone ?? ""
  const zoneOptions = currentTz && !TIME_ZONES.includes(currentTz)
    ? [currentTz, ...TIME_ZONES]
    : TIME_ZONES

  return (
    <>
      <SettingsRow
        label="Time zone"
        description="How dates and times are displayed across the app"
      >
        <Select
          size="sm"
          aria-label="Time zone"
          value={currentTz}
          onChange={(e) => setTimezone(e.target.value)}
          disabled={!data}
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
          value={theme}
          onChange={(e) => setThemeChoice(e.target.value as ThemeChoice)}
        >
          {THEMES.map((t) => (
            <option key={t.value} value={t.value}>
              {t.label}
            </option>
          ))}
        </Select>
      </SettingsRow>
    </>
  )
}

/** Account: identity + preferences (one Profile card), authentication, and active
 *  sessions — rendered inline on the settings page. */
export function SecurityDetail(_: DetailComponentProps) {
  return (
    <div className="flex flex-col gap-4">
      <AccountContent>
        <PreferenceRows />
      </AccountContent>
      <ActiveSessionsCard />
    </div>
  )
}
