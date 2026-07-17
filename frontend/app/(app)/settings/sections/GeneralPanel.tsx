"use client"

import { useEffect, useMemo, useRef, useState } from "react"

import { Button } from "@/components/ui/Button"
import { Input } from "@/components/ui/Input"
import { AuthSecurityPolicyCard } from "@/components/settings/AuthSecurityPolicyCard"
import { SettingsCard } from "@/components/settings/SettingsCard"
import { SettingsRow } from "@/components/settings/SettingsRow"
import {
  clearOrgLogo,
  saveOrgSettings,
  setOrgLogo,
  useOrgSettings,
  type OrgSettings,
} from "@/lib/client/settings/use-org-settings"
import { useSaveBarSection } from "@/app/(app)/settings/save-bar/SaveBarProvider"
import type { DetailComponentProps } from "../registry"

type EditableFields = Pick<OrgSettings, "name">

export function GeneralDetail(_: DetailComponentProps) {
  const { data, mutate } = useOrgSettings()
  const [draft, setDraft] = useState<EditableFields | null>(null)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [logoError, setLogoError] = useState<string | null>(null)
  const fileInputRef = useRef<HTMLInputElement>(null)

  useEffect(() => {
    if (!data) return
    // Keep an in-progress name edit when `data` changes for an unrelated reason
    // (an immediate logo save mutates the same cache entry); only sync a clean
    // or unset draft.
    setDraft((prev) => (prev && prev.name !== data.name ? prev : { name: data.name }))
  }, [data])

  const isDirty = !!data && !!draft && draft.name !== data.name

  const initials = useMemo(() => {
    const seed = (draft?.name || "Org").trim()
    return seed.slice(0, 2).toUpperCase()
  }, [draft?.name])

  const handleSave = async () => {
    if (!draft) return
    setSaving(true)
    setError(null)
    try {
      const next = await saveOrgSettings(draft)
      mutate(next)
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to save.")
    } finally {
      setSaving(false)
    }
  }

  const handleDiscard = () => {
    if (data) setDraft({ name: data.name })
    setError(null)
  }

  useSaveBarSection({
    id: "general",
    dirty: isDirty,
    saving,
    count: Number(isDirty),
    error,
    onSave: handleSave,
    onDiscard: handleDiscard,
  })

  const handleLogoFile = async (file: File) => {
    setLogoError(null)
    if (file.size > 100 * 1024) {
      setLogoError("Logo too large. Keep under 100 KB.")
      return
    }
    const reader = new FileReader()
    reader.onload = async () => {
      const dataUrl = String(reader.result ?? "")
      try {
        const next = await setOrgLogo(dataUrl)
        mutate(next)
      } catch (e) {
        setLogoError(e instanceof Error ? e.message : "Upload failed.")
      }
    }
    reader.readAsDataURL(file)
  }

  const handleLogoClear = async () => {
    setLogoError(null)
    try {
      const next = await clearOrgLogo()
      mutate(next)
    } catch (e) {
      setLogoError(e instanceof Error ? e.message : "Failed to clear logo.")
    }
  }

  return (
    <div className="flex flex-col gap-4">
      <SettingsCard heading="Identity">
        <SettingsRow
          label="Organization name"
          layout="stack"
          description="Shown in the sidebar, login page, and browser tab title. Leave blank to use the default Aegis branding."
        >
          <Input
            aria-label="Organization name"
            placeholder="Blu3Raven"
            className="max-w-xl"
            value={draft?.name ?? ""}
            onChange={(e) => setDraft((d) => (d ? { ...d, name: e.target.value || null } : d))}
          />
        </SettingsRow>
        <SettingsRow label="Logo" description="PNG / SVG / JPEG · max 100 KB · square works best">
          {data?.logoDataUrl ? (
            <img src={data.logoDataUrl} alt="Org logo" className="h-9 w-9 shrink-0 rounded-md object-contain" />
          ) : (
            <div
              aria-hidden="true"
              className="grid h-9 w-9 shrink-0 place-items-center rounded-md bg-[var(--color-accent)] text-xs font-bold text-white"
            >
              {initials}
            </div>
          )}
          <input
            ref={fileInputRef}
            type="file"
            accept="image/png,image/jpeg,image/svg+xml,image/webp"
            className="hidden"
            onChange={(e) => {
              const f = e.target.files?.[0]
              if (f) void handleLogoFile(f)
              e.target.value = ""
            }}
          />
          <Button variant="secondary" size="sm" onClick={() => fileInputRef.current?.click()}>
            Upload
          </Button>
          {data?.logoDataUrl && (
            <Button variant="secondary" size="sm" onClick={handleLogoClear}>
              Clear
            </Button>
          )}
          {logoError && <span role="alert" className="text-xs text-[var(--color-severity-critical-text)]">{logoError}</span>}
        </SettingsRow>
      </SettingsCard>
      <AuthSecurityPolicyCard />
    </div>
  )
}
