"use client"

import { useState } from "react"

import { SettingsCard } from "@/components/settings/SettingsCard"
import { SettingsRow } from "@/components/settings/SettingsRow"
import { SettingsSection } from "@/components/settings/SettingsSection"
import { ToggleSwitch } from "@/components/settings/ToggleSwitch"

interface NotifPref {
  key: string
  label: string
  /** What triggers the notification — appears under the row label */
  trigger: string
  /** Channel label that lives next to the toggle */
  channel: string
  defaultEnabled: boolean
}

const PREFS: NotifPref[] = [
  {
    key: "assignments",
    label: "Assignments",
    trigger: "When someone assigns you a finding",
    channel: "In-app + email",
    defaultEnabled: true,
  },
  {
    key: "mentions",
    label: "Mentions",
    trigger: "When you're @-mentioned in a comment",
    channel: "In-app + Slack DM",
    defaultEnabled: true,
  },
  {
    key: "kev",
    label: "KEV updates on your repos",
    trigger: "When CISA flags a CVE that affects code you work on",
    channel: "In-app only",
    defaultEnabled: true,
  },
  {
    key: "weekly_digest",
    label: "Weekly digest",
    trigger: "Monday 9am · what changed this week",
    channel: "Email",
    defaultEnabled: true,
  },
  {
    key: "marketing",
    label: "Marketing & product updates",
    trigger: "Major releases · roughly monthly",
    channel: "Email only",
    defaultEnabled: false,
  },
]

export function NotificationsPreferencesSection() {
  const [prefs, setPrefs] = useState<Record<string, boolean>>(() =>
    Object.fromEntries(PREFS.map((p) => [p.key, p.defaultEnabled])),
  )

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
              checked={prefs[pref.key]}
              onChange={(next) =>
                setPrefs((current) => ({ ...current, [pref.key]: next }))
              }
            />
          </SettingsRow>
        ))}
      </SettingsCard>
    </SettingsSection>
  )
}
