"use client"

import { useEffect, useState } from "react"

import { useSaveBarSection } from "@/app/(app)/settings/save-bar/SaveBarProvider"
import { SettingsCard } from "@/components/settings/SettingsCard"
import { SettingsRow } from "@/components/settings/SettingsRow"
import { ToggleSwitch } from "@/components/settings/ToggleSwitch"
import { Select } from "@/components/ui/Select"
import {
  saveAuthSecurity,
  useAuthSecurity,
  type AuthSecuritySettings,
  type RecoveryCodePolicy,
} from "@/lib/client/settings/use-auth-security"

const SESSION_DURATIONS: { value: number; label: string }[] = [
  { value: 1, label: "1 day" },
  { value: 7, label: "7 days" },
  { value: 14, label: "14 days" },
  { value: 30, label: "30 days" },
  { value: 60, label: "60 days" },
  { value: 90, label: "90 days" },
]

const RECOVERY_POLICIES: { value: RecoveryCodePolicy; label: string }[] = [
  { value: "mandatory", label: "Mandatory" },
  { value: "optional", label: "Optional" },
  { value: "disabled", label: "Disabled" },
]

function diffCount(a: AuthSecuritySettings, b: AuthSecuritySettings): number {
  let n = 0
  if (a.requireMfaManualUsers !== b.requireMfaManualUsers) n++
  if (a.requireMfaAdmins !== b.requireMfaAdmins) n++
  if (a.trustedSessionDurationDays !== b.trustedSessionDurationDays) n++
  if (a.recoveryCodePolicy !== b.recoveryCodePolicy) n++
  return n
}

export function AuthSecurityPolicyCard() {
  const { data, error: loadError, mutate } = useAuthSecurity()
  const [draft, setDraft] = useState<AuthSecuritySettings | null>(data)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    if (data) setDraft(data)
  }, [data])

  const changeCount = data && draft ? diffCount(data, draft) : 0
  const isDirty = changeCount > 0

  const handleSave = async () => {
    if (!draft) return
    setSaving(true)
    setError(null)
    try {
      const next = await saveAuthSecurity(draft)
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
    id: "auth-security-policy",
    dirty: isDirty,
    saving,
    count: changeCount,
    error,
    onSave: handleSave,
    onDiscard: handleDiscard,
  })

  if (loadError?.code === "PERMISSION_DENIED") {
    return (
      <SettingsCard heading="Authentication Policy">
        <p className="text-sm text-[var(--color-text-secondary)]">
          You don&apos;t have permission to view authentication policy settings.
          Contact an admin to make changes.
        </p>
      </SettingsCard>
    )
  }

  return (
    <SettingsCard heading="Authentication Policy">
      <SettingsRow
        label="Require MFA for password-based users"
        description="Force every manually provisioned user to enrol an authenticator before signing in."
      >
        <ToggleSwitch
          label="Require MFA for password-based users"
          checked={draft?.requireMfaManualUsers ?? false}
          onChange={(next) =>
            setDraft((d) => (d ? { ...d, requireMfaManualUsers: next } : d))
          }
        />
      </SettingsRow>
      <SettingsRow
        label="Require MFA for admins"
        description="Admins always need a second factor, even if MFA is optional for everyone else."
      >
        <ToggleSwitch
          label="Require MFA for admins"
          checked={draft?.requireMfaAdmins ?? false}
          onChange={(next) =>
            setDraft((d) => (d ? { ...d, requireMfaAdmins: next } : d))
          }
        />
      </SettingsRow>
      <SettingsRow
        label="Trusted session duration"
        description="How long a remember-me cookie stays valid before MFA is required again."
      >
        <Select
          size="sm"
          aria-label="Trusted session duration"
          value={String(draft?.trustedSessionDurationDays ?? 30)}
          onChange={(e) =>
            setDraft((d) =>
              d
                ? { ...d, trustedSessionDurationDays: Number(e.target.value) }
                : d,
            )
          }
        >
          {SESSION_DURATIONS.map((opt) => (
            <option key={opt.value} value={opt.value}>
              {opt.label}
            </option>
          ))}
        </Select>
      </SettingsRow>
      <SettingsRow
        label="Recovery code policy"
        description="Whether users must generate recovery codes when enrolling MFA."
      >
        <Select
          size="sm"
          aria-label="Recovery code policy"
          value={draft?.recoveryCodePolicy ?? "mandatory"}
          onChange={(e) =>
            setDraft((d) =>
              d
                ? {
                    ...d,
                    recoveryCodePolicy: e.target.value as RecoveryCodePolicy,
                  }
                : d,
            )
          }
        >
          {RECOVERY_POLICIES.map((opt) => (
            <option key={opt.value} value={opt.value}>
              {opt.label}
            </option>
          ))}
        </Select>
      </SettingsRow>
    </SettingsCard>
  )
}
