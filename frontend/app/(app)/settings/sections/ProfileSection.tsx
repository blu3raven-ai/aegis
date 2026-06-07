"use client"

import { useEffect, useState } from "react"

import { SettingsCard } from "@/components/settings/SettingsCard"
import { SettingsRow } from "@/components/settings/SettingsRow"
import { SettingsSection } from "@/components/settings/SettingsSection"

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

const THEME_STORAGE_KEY = "aegis:settings:theme"
const TZ_STORAGE_KEY = "aegis:settings:timezone"

/**
 * Profile renders personal *preferences only*. Identity (avatar, username,
 * email) lives on AccountContent under Security & sessions so the same edit
 * flow isn't duplicated.
 */
export function ProfileSection() {
  const [timezone, setTimezone] = useState<string>("")
  const [theme, setTheme] = useState<ThemeValue>("system")

  // Hydrate from localStorage and the browser-detected timezone on mount —
  // SSR has neither so the default state is empty/system.
  useEffect(() => {
    const detected =
      Intl.DateTimeFormat().resolvedOptions().timeZone ?? "UTC"
    const storedTz = window.localStorage.getItem(TZ_STORAGE_KEY)
    setTimezone(storedTz ?? detected)

    const storedTheme = window.localStorage.getItem(THEME_STORAGE_KEY)
    if (storedTheme === "dark" || storedTheme === "light" || storedTheme === "system") {
      setTheme(storedTheme)
    }
  }, [])

  const handleTimezoneChange = (next: string) => {
    setTimezone(next)
    if (typeof window !== "undefined") {
      window.localStorage.setItem(TZ_STORAGE_KEY, next)
    }
  }

  const handleThemeChange = (next: ThemeValue) => {
    setTheme(next)
    if (typeof window !== "undefined") {
      window.localStorage.setItem(THEME_STORAGE_KEY, next)
    }
  }

  // Surface the detected zone in the dropdown even if it isn't in the curated
  // list — admins shouldn't lose their actual locale.
  const zoneOptions = timezone && !TIME_ZONES.includes(timezone)
    ? [timezone, ...TIME_ZONES]
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
          <select
            aria-label="Time zone"
            value={timezone}
            onChange={(e) => handleTimezoneChange(e.target.value)}
            className={selectClass}
          >
            {zoneOptions.map((tz) => (
              <option key={tz} value={tz}>
                {tz}
              </option>
            ))}
          </select>
        </SettingsRow>
        <SettingsRow label="Theme" description="Affects this device only">
          <select
            aria-label="Theme"
            value={theme}
            onChange={(e) => handleThemeChange(e.target.value as ThemeValue)}
            className={selectClass}
          >
            {THEMES.map((t) => (
              <option key={t.value} value={t.value}>
                {t.label}
              </option>
            ))}
          </select>
        </SettingsRow>
      </SettingsCard>
    </SettingsSection>
  )
}

const selectClass =
  "appearance-none rounded-md border border-[var(--color-border-strong)] bg-[var(--color-bg)] px-3 py-1.5 text-sm text-[var(--color-text-primary)] outline-none focus:border-[var(--color-accent)]"
