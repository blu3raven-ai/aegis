"use client"

import { useState, useTransition } from "react"
import { useRouter } from "next/navigation"
import { saveToolSettings } from "@/lib/client/settings-api"
import { useSaveBarSection } from "../save-bar/SaveBarProvider"
import { PrerequisitePanel } from "../PrerequisitePanel"
import type { PrerequisiteItem } from "@/lib/shared/prerequisite-utils"
import { SettingsCard } from "@/components/shared/SettingsCard"
import { Input } from "@/components/ui/Input"

interface SecretsSetupFormProps {
  initialValues: {
    scanConcurrency: string
    scanDepth: string
    scanHistoryWindow: string
    autoRerunEnabled: boolean
    rerunScheduleType: "simple" | "cron"
    rerunScheduleValue: string
  }
  prereqItems: PrerequisiteItem[]
  prereqRefreshing: boolean
  refreshPrereqs: () => void
  canEnable: boolean
  canEdit?: boolean
}

export function SecretsSetupForm({
  initialValues,
  prereqItems,
  prereqRefreshing,
  refreshPrereqs,
  canEnable,
  canEdit = true,
}: SecretsSetupFormProps) {
  const normalizedInitialValues = {
    scanConcurrency: initialValues.scanConcurrency ?? "4",
    scanDepth: initialValues.scanDepth ?? "light",
    scanHistoryWindow: initialValues.scanHistoryWindow ?? "all",
    autoRerunEnabled: Boolean(initialValues.autoRerunEnabled),
    rerunScheduleType: initialValues.rerunScheduleType ?? "simple",
    rerunScheduleValue: initialValues.rerunScheduleValue ?? "02:00",
  }
  const [values, setValues] = useState(normalizedInitialValues)
  const [error, setError] = useState<string | null>(null)
  const [saved, setSaved] = useState(false)
  const [isPending, startTransition] = useTransition()
  const router = useRouter()

  const isDirty =
    values.scanConcurrency !== normalizedInitialValues.scanConcurrency ||
    values.scanDepth !== normalizedInitialValues.scanDepth ||
    values.autoRerunEnabled !== normalizedInitialValues.autoRerunEnabled ||
    values.rerunScheduleType !== normalizedInitialValues.rerunScheduleType ||
    values.rerunScheduleValue !== normalizedInitialValues.rerunScheduleValue

  // Status determination
  let status: "Setup required" | "Verifying" | "Ready" = "Setup required"
  if (prereqRefreshing) {
    status = "Verifying"
  } else if (canEnable) {
    status = "Ready"
  }

  function handleSave() {
    setError(null)

    startTransition(async () => {
      const result = await saveToolSettings({
        tool: "secrets",
        enabled: true,
        settings: {
          scanConcurrency: values.scanConcurrency,
          scanDepth: values.scanDepth,
          scanHistoryWindow: values.scanHistoryWindow,
          autoRerunEnabled: values.autoRerunEnabled ? "true" : "false",
          rerunScheduleType: values.rerunScheduleType,
          rerunScheduleValue: values.rerunScheduleValue,
        },
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
    setValues(normalizedInitialValues)
    setError(null)
    setSaved(false)
  }

  useSaveBarSection({
    id: "secrets-setup",
    dirty: isDirty,
    saving: isPending,
    onSave: handleSave,
    onDiscard: handleDiscard,
  })

  return (
    <div className="space-y-6">
      {!canEdit && (
        <div className="rounded-lg border border-[var(--color-state-pending-border)] bg-[var(--color-state-pending-subtle)] px-4 py-2.5 text-xs text-[var(--color-state-pending)]">
          Only owners and admins can edit tool settings.
        </div>
      )}

      <PrerequisitePanel
        title="Scanner Verification"
        description="Verifies that the scanner image is available and trusted on the runner."
        items={prereqItems}
        onRefresh={refreshPrereqs}
        isRefreshing={prereqRefreshing}
      />

      {/* Default Scan Depth — primary config, shown first */}
      <SettingsCard eyebrow="Scanner Config" title="Default Scan Depth" subtitle="Choose the default scanning depth for new scans.">
      <fieldset disabled={!canEdit} className="space-y-3 disabled:opacity-50">
        <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
          {(
            [
              { value: "light", label: "Light", desc: "Scans current code only. Fast — typically completes in minutes." },
              { value: "deep", label: "Deep", desc: "Scans full git history for leaked secrets. Thorough but can take hours on large repos." },
            ] as const
          ).map((opt) => (
            <button
              key={opt.value}
              type="button"
              disabled={!canEdit}
              onClick={() => setValues({ ...values, scanDepth: opt.value })}
              className={`rounded-xl border p-3 text-left transition-colors disabled:cursor-not-allowed disabled:opacity-50 ${
                values.scanDepth === opt.value
                  ? "border-[var(--color-accent)] bg-[var(--color-accent-subtle)]"
                  : "border-[var(--color-border)] hover:border-[var(--color-text-secondary)]"
              }`}
            >
              <div className="flex items-center gap-2">
                <span className={`h-2 w-2 rounded-full ${values.scanDepth === opt.value ? "bg-[var(--color-accent)]" : "bg-[var(--color-text-secondary)]"}`} />
                <span className={`text-sm font-semibold ${values.scanDepth === opt.value ? "text-[var(--color-accent)]" : "text-[var(--color-text-primary)]"}`}>
                  {opt.label}
                </span>
              </div>
              <p className="mt-1.5 text-xs leading-relaxed text-[var(--color-text-secondary)]">
                {opt.desc}
              </p>
            </button>
          ))}
        </div>

        {/* How far back to scan — slider */}
        {(() => {
          const WINDOW_STEPS = [
            { value: "30d", label: "Last month" },
            { value: "90d", label: "Last 3 months" },
            { value: "180d", label: "Last 6 months" },
            { value: "365d", label: "Last year" },
            { value: "all", label: "Everything" },
          ] as const
          const stepIndex = WINDOW_STEPS.findIndex((s) => s.value === values.scanHistoryWindow)
          const activeIndex = stepIndex === -1 ? 0 : stepIndex
          return (
            <div>
              <div className="mb-2 flex items-baseline justify-between">
                <label className="text-xs font-medium text-[var(--color-text-primary)]">
                  How far back to scan
                </label>
                <span className="text-xs font-medium text-[var(--color-accent)]">
                  {WINDOW_STEPS[activeIndex].label}
                </span>
              </div>
              <input
                type="range"
                min={0}
                max={WINDOW_STEPS.length - 1}
                step={1}
                value={activeIndex}
                disabled={!canEdit}
                onChange={(e) =>
                  setValues({ ...values, scanHistoryWindow: WINDOW_STEPS[Number(e.target.value)].value })
                }
                className="w-full accent-[var(--color-accent)] disabled:cursor-not-allowed disabled:opacity-50"
              />
              <div className="mt-1 flex justify-between">
                {WINDOW_STEPS.map((s) => (
                  <span key={s.value} className="text-2xs text-[var(--color-text-secondary)]">
                    {s.label.replace("Last ", "")}
                  </span>
                ))}
              </div>
              <p className="mt-1.5 text-xs text-[var(--color-text-secondary)]">
                Controls how much commit history is scanned each run. Shorter windows mean faster scans but may miss older secrets.
              </p>
            </div>
          )
        })()}
      </fieldset>
      </SettingsCard>

      <SettingsCard eyebrow="Scanner Config" title="Scanner Settings">
      <fieldset disabled={!canEdit} className="space-y-4 disabled:opacity-50">
            <div>
              <label className="mb-1.5 block text-xs font-medium text-[var(--color-text-primary)]">
                Scan concurrency
              </label>
              <Input
                type="number"
                min="1"
                value={values.scanConcurrency}
                onChange={(e) => setValues({ ...values, scanConcurrency: e.target.value })}
              />
              <p className="mt-1.5 text-xs text-[var(--color-text-secondary)]">
                Maximum repositories scanned in parallel.
              </p>
            </div>

      </fieldset>
      </SettingsCard>

      <SettingsCard eyebrow="Automation" title="Scheduled Scans">
      <fieldset disabled={!canEdit} className="space-y-4 disabled:opacity-50">
          <div className="space-y-4">
            <label className="flex items-start gap-3 rounded-lg border border-[var(--color-border)] bg-[var(--color-surface)] px-3 py-3 text-sm">
              <input
                type="checkbox"
                checked={values.autoRerunEnabled}
                onChange={(e) => setValues({ ...values, autoRerunEnabled: e.target.checked })}
                className="mt-0.5 h-4 w-4 rounded border-[var(--color-border)] text-[var(--color-accent)] focus:ring-[var(--color-accent)]/30"
              />
              <span>
                <span className="block font-medium text-[var(--color-text-primary)]">Enable daily auto-rerun</span>
                <span className="mt-1 block text-xs text-[var(--color-text-secondary)]">
                  Automatically trigger a full scan of all selected organizations once per day.
                </span>
              </span>
            </label>

            {values.autoRerunEnabled && (
              <div className="space-y-4 rounded-lg border border-[var(--color-border)] p-4">
                <div className="flex flex-col gap-4 sm:flex-row sm:items-center">
                  {values.rerunScheduleType === "simple" ? (
                    <div className="flex-1">
                      <label className="mb-1.5 block text-xs font-medium text-[var(--color-text-primary)]">
                        Scan Time (Daily)
                      </label>
                      <Input
                        type="time"
                        value={values.rerunScheduleValue}
                        onChange={(e) => setValues({ ...values, rerunScheduleValue: e.target.value })}
                        className="max-w-[150px]"
                      />
                    </div>
                  ) : (
                    <div className="flex-1">
                      <label className="mb-1.5 block text-xs font-medium text-[var(--color-text-primary)]">
                        Cron Expression
                      </label>
                      <Input
                        type="text"
                        value={values.rerunScheduleValue}
                        onChange={(e) => setValues({ ...values, rerunScheduleValue: e.target.value })}
                        placeholder="e.g. 0 2 * * *"
                        className="font-mono"
                      />
                      <p className="mt-1.5 text-xs text-[var(--color-text-secondary)]">
                        Standard cron format (min hour day month weekday).
                      </p>
                    </div>
                  )}
                </div>

                <div className="flex items-center gap-3">
                  <label className="inline-flex items-center gap-2 text-sm text-[var(--color-text-primary)]">
                    <input
                      type="checkbox"
                      checked={values.rerunScheduleType === "cron"}
                      onChange={(e) => {
                        const isCron = e.target.checked
                        setValues({
                          ...values,
                          rerunScheduleType: isCron ? "cron" : "simple",
                          rerunScheduleValue: isCron ? "0 2 * * *" : "02:00"
                        })
                      }}
                      className="h-4 w-4 rounded border-[var(--color-border)] text-[var(--color-accent)] focus:ring-[var(--color-accent)]/30"
                    />
                    Use custom cron expression
                  </label>
                </div>
              </div>
            )}
          </div>
      </fieldset>
      </SettingsCard>

      {error && (
        <div className="rounded-lg border border-[var(--color-severity-critical-border)] bg-[var(--color-severity-critical-subtle)] px-3 py-2.5 text-sm text-[var(--color-severity-critical)]">
          {error}
        </div>
      )}

    </div>
  )
}
