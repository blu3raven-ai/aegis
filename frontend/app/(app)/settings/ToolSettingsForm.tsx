"use client"

import { useEffect, useState, useTransition } from "react"
import { useRouter } from "next/navigation"
import { saveToolSettings } from "@/lib/client/settings-api"
import { SaveBar } from "./SaveBar"

type ToolKey = "dependencies" | "containerScanning" | "codeScanning" | "secrets" | "iacSecurity"

interface FieldConfig {
  key: string
  label: string
  type: "number" | "text" | "password" | "checkbox"
  help: string
  required?: boolean
}

export type ToolSettingsDraft = {
  enabled: boolean
  values: Record<string, string>
}

interface Props {
  tool: ToolKey
  title: string
  description: string
  enabled: boolean
  fields: FieldConfig[]
  initialValues: Record<string, string>
  disableEnable?: { reason: string } | ((draft: ToolSettingsDraft) => { reason: string } | undefined)
  onDraftChange?: (draft: ToolSettingsDraft) => void
  canEdit?: boolean
}

export function ToolSettingsForm({
  tool,
  title,
  description,
  enabled,
  fields,
  initialValues,
  disableEnable,
  onDraftChange,
  canEdit = true,
}: Props) {
  const [isEnabled, setIsEnabled] = useState(enabled)
  const [values, setValues] = useState<Record<string, string>>(initialValues)
  const [error, setError] = useState<string | null>(null)
  const [saved, setSaved] = useState(false)
  const [isPending, startTransition] = useTransition()
  const router = useRouter()
  const draft: ToolSettingsDraft = {
    enabled: isEnabled,
    values,
  }
  const computedDisableEnable =
    typeof disableEnable === "function" ? disableEnable(draft) : disableEnable

  const isDirty =
    isEnabled !== enabled ||
    Object.keys(initialValues).some((k) => values[k] !== initialValues[k])

  function handleSave() {
    setError(null)
    if (computedDisableEnable && isEnabled) {
      setError(computedDisableEnable.reason)
      return
    }
    startTransition(async () => {
      const result = await saveToolSettings({
        tool,
        enabled: isEnabled,
        settings: values,
      })
      if (!result.ok) {
        setError(result.error)
        return
      }
      setSaved(true)
      setTimeout(() => setSaved(false), 2000)
      router.refresh()
    })
  }

  function handleDiscard() {
    setIsEnabled(enabled)
    setValues(initialValues)
    setError(null)
    setSaved(false)
  }

  useEffect(() => {
    onDraftChange?.(draft)
  }, [isEnabled, values, onDraftChange])

  function setFieldValue(key: string, value: string) {
    setValues((prev) => ({ ...prev, [key]: value }))
  }

  function onSubmit(e: React.FormEvent) {
    e.preventDefault()
    handleSave()
  }

  return (
    <form onSubmit={onSubmit} className="space-y-6">
      <div className="flex items-start justify-between gap-4">
        <div>
          <h2 className="text-base font-semibold text-[var(--color-text-primary)]">{title}</h2>
          <p className="mt-1 text-sm text-[var(--color-text-secondary)]">{description}</p>
        </div>
        <div className="flex flex-col items-end gap-1">
          <label
            className={`inline-flex items-center gap-2 text-sm ${
              (computedDisableEnable && !isEnabled) || !canEdit
                ? "cursor-not-allowed opacity-50 text-[var(--color-text-secondary)]"
                : "text-[var(--color-text-primary)]"
            }`}
          >
            <input
              type="checkbox"
              checked={isEnabled}
              disabled={Boolean((computedDisableEnable && !isEnabled) || !canEdit)}
              onChange={(e) => setIsEnabled(e.target.checked)}
              className="h-4 w-4 rounded border-[var(--color-border)] text-[var(--color-accent)] focus:ring-[var(--color-accent)]/30 disabled:cursor-not-allowed"
            />
            Enabled
          </label>
          {!canEdit && (
            <p className="max-w-[220px] text-right text-xs text-[var(--color-state-pending)]">
              Only owners and admins can edit tool settings.
            </p>
          )}
          {computedDisableEnable && (
            <p className="max-w-[220px] text-right text-xs text-[var(--color-state-pending)]">
              {computedDisableEnable.reason}
            </p>
          )}
        </div>
      </div>

      <fieldset disabled={!isEnabled || !canEdit} className="space-y-4 disabled:opacity-50">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {fields.map((field) => (
            <div key={field.key}>
              {field.type === "checkbox" ? (
                <label className="flex items-start gap-3 rounded-lg border border-[var(--color-border)] bg-[var(--color-surface)] px-3 py-3 text-sm text-[var(--color-text-primary)]">
                  <input
                    type="checkbox"
                    checked={values[field.key] === "true"}
                    onChange={(e) => setFieldValue(field.key, e.target.checked ? "true" : "false")}
                    className="mt-0.5 h-4 w-4 rounded border-[var(--color-border)] text-[var(--color-accent)] focus:ring-[var(--color-accent)]/30"
                  />
                  <span>
                    <span className="block font-medium">{field.label}</span>
                    <span className="mt-1 block text-xs text-[var(--color-text-secondary)]">{field.help}</span>
                  </span>
                </label>
              ) : (
                <>
                  <label className="mb-2 block text-2xs font-bold uppercase tracking-[0.14em] text-[var(--color-text-secondary)]">{field.label}</label>
                  <input
                    type={field.type}
                    min={field.type === "number" ? 1 : undefined}
                    value={values[field.key] ?? ""}
                    onChange={(e) => setFieldValue(field.key, e.target.value)}
                    required={field.required ?? true}
                    className="w-full rounded-lg border border-[var(--color-border)] bg-[var(--color-surface)] px-3 py-2.5 text-sm text-[var(--color-text-primary)] focus:outline-none focus:ring-2 focus:ring-[var(--color-accent)]/30"
                  />
                  <p className="mt-1.5 text-xs text-[var(--color-text-secondary)]">{field.help}</p>
                </>
              )}
            </div>
          ))}
        </div>
      </fieldset>

      {error && (
        <div className="rounded-lg bg-[var(--color-severity-critical-subtle)] border border-[var(--color-severity-critical-border)] px-3 py-2.5 text-sm text-[var(--color-severity-critical)]">
          {error}
        </div>
      )}

      <SaveBar
        saved={saved}
        dirty={isDirty}
        onSave={handleSave}
        onDiscard={handleDiscard}
        saving={isPending}
      />
    </form>
  )
}
