"use client"

import { useState, useTransition } from "react"
import { useRouter } from "next/navigation"
import { PrerequisitePanel } from "../PrerequisitePanel"
import { SaveBar } from "../SaveBar"
import type { PrerequisiteItem } from "@/lib/shared/prerequisite-utils"
import { RulesetPicker } from "./RulesetPicker"
import { parseRulesets, serialiseRulesets, AUTO_RULESETS } from "@/lib/shared/code-scanning-rulesets"
import { SettingsCard } from "@/components/shared/SettingsCard"

interface CodeScanningSetupFormProps {
  initialScanConcurrency: string
  initialRulesets: string
  initialAutoRerunEnabled: boolean
  initialRerunScheduleType: "simple" | "cron"
  initialRerunScheduleValue: string
  prereqItems: PrerequisiteItem[]
  prereqRefreshing: boolean
  refreshPrereqs: () => void
  canEnable: boolean
  passingCount: number
  totalCount: number
  canEdit?: boolean
  languageSupport?: React.ReactNode
}

export function CodeScanningSetupForm({
  initialScanConcurrency,
  initialRulesets,
  initialAutoRerunEnabled,
  initialRerunScheduleType,
  initialRerunScheduleValue,
  prereqItems,
  prereqRefreshing,
  refreshPrereqs,
  canEnable,
  passingCount,
  totalCount,
  canEdit = true,
  languageSupport,
}: CodeScanningSetupFormProps) {
  const normalizedInitial = {
    scanConcurrency: initialScanConcurrency ?? "4",
    rulesets: parseRulesets(initialRulesets),
    autoRerunEnabled: Boolean(initialAutoRerunEnabled),
    rerunScheduleType: initialRerunScheduleType ?? "simple",
    rerunScheduleValue: initialRerunScheduleValue ?? "02:00",
  }

  const [values, setValues] = useState(normalizedInitial)
  const [error, setError] = useState<string | null>(null)
  const [saved, setSaved] = useState(false)
  const [isPending, startTransition] = useTransition()
  const router = useRouter()

  const isDirty =
    values.scanConcurrency !== normalizedInitial.scanConcurrency ||
    serialiseRulesets(values.rulesets) !== serialiseRulesets(normalizedInitial.rulesets) ||
    values.autoRerunEnabled !== normalizedInitial.autoRerunEnabled ||
    values.rerunScheduleType !== normalizedInitial.rerunScheduleType ||
    values.rerunScheduleValue !== normalizedInitial.rerunScheduleValue

  function handleSave() {
    setError(null)

    if (values.rulesets.length === 0) {
      setError("At least one ruleset must be selected.")
      return
    }

    startTransition(async () => {
      const { saveToolSettings } = await import("@/lib/client/settings-api")
      const result = await saveToolSettings({
        tool: "codeScanning",
        enabled: true,
        settings: {
          scanConcurrency: values.scanConcurrency,
          rulesets: serialiseRulesets([...values.rulesets, ...AUTO_RULESETS]),
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
    setValues(normalizedInitial)
    setError(null)
    setSaved(false)
  }

  let status: "Setup required" | "Verifying" | "Ready" = "Setup required"
  if (prereqRefreshing) {
    status = "Verifying"
  } else if (canEnable) {
    status = "Ready"
  }

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
        summary={undefined}
      />

      {/* Default Rulesets — primary config, shown first */}
      <SettingsCard eyebrow="Rulesets" title="Default Rulesets" subtitle="Select the security rule packs to apply during each scan. Language and framework packs are always included automatically.">
      <fieldset disabled={!canEdit} className="space-y-3 disabled:opacity-50">
        <RulesetPicker
          selected={values.rulesets}
          onChange={(rulesets) => setValues({ ...values, rulesets })}
          disabled={!canEdit}
        />
      </fieldset>
      {languageSupport && <div className="mt-4">{languageSupport}</div>}
      </SettingsCard>

      <SettingsCard eyebrow="Scanner Config" title="Scanner Settings">
      <fieldset disabled={!canEdit} className="space-y-4 disabled:opacity-50">
          <div>
            <label className="mb-1.5 block text-xs font-medium text-[var(--color-text-primary)]">Scan concurrency</label>
            <input
              type="number"
              min="1"
              value={values.scanConcurrency}
              onChange={(e) => setValues({ ...values, scanConcurrency: e.target.value })}
              className="w-full rounded-lg border border-[var(--color-border)] bg-[var(--color-surface)] px-3 py-2 text-sm text-[var(--color-text-primary)] focus:outline-none focus:ring-2 focus:ring-[var(--color-accent)]/30"
            />
            <p className="mt-1.5 text-xs text-[var(--color-text-secondary)]">Maximum repositories scanned in parallel.</p>
          </div>

      </fieldset>
      </SettingsCard>

      <SettingsCard eyebrow="Automation" title="Scheduled Scans">
      <fieldset disabled={!canEdit} className="space-y-4 disabled:opacity-50">
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
                    <input
                      type="time"
                      value={values.rerunScheduleValue}
                      onChange={(e) => setValues({ ...values, rerunScheduleValue: e.target.value })}
                      className="w-full max-w-[150px] rounded-lg border border-[var(--color-border)] bg-[var(--color-surface)] px-3 py-2 text-sm text-[var(--color-text-primary)] focus:outline-none focus:ring-2 focus:ring-[var(--color-accent)]/30"
                    />
                  </div>
                ) : (
                  <div className="flex-1">
                    <label className="mb-1.5 block text-xs font-medium text-[var(--color-text-primary)]">
                      Cron Expression
                    </label>
                    <input
                      type="text"
                      value={values.rerunScheduleValue}
                      onChange={(e) => setValues({ ...values, rerunScheduleValue: e.target.value })}
                      placeholder="e.g. 0 2 * * *"
                      className="w-full rounded-lg border border-[var(--color-border)] bg-[var(--color-surface)] px-3 py-2 text-sm font-mono text-[var(--color-text-primary)] focus:outline-none focus:ring-2 focus:ring-[var(--color-accent)]/30"
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
                        rerunScheduleValue: isCron ? "0 2 * * *" : "02:00",
                      })
                    }}
                    className="h-4 w-4 rounded border-[var(--color-border)] text-[var(--color-accent)] focus:ring-[var(--color-accent)]/30"
                  />
                  Use custom cron expression
                </label>
              </div>
            </div>
          )}
      </fieldset>
      </SettingsCard>

      {error && (
        <div className="rounded-lg border border-[var(--color-severity-critical-border)] bg-[var(--color-severity-critical-subtle)] px-3 py-2.5 text-sm text-[var(--color-severity-critical)]">
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
    </div>
  )
}
