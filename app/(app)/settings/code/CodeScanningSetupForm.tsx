"use client"

import { useState, useTransition } from "react"
import { useRouter } from "next/navigation"
import { PrerequisitePanel } from "../PrerequisitePanel"
import { SaveBar } from "../SaveBar"
import type { PrerequisiteItem } from "@/lib/shared/prerequisite-utils"
import { RulesetPicker } from "@/app/(app)/code/_components/RulesetPicker"
import { parseRulesets, serialiseRulesets, AUTO_RULESETS } from "@/lib/shared/code-scanning-rulesets"
import { SettingsCard } from "@/components/shared/SettingsCard"

interface CodeScanningSetupFormProps {
  initialScanConcurrency: string
  initialRulesets: string
  initialAiReviewEnabled: boolean
  initialAiApiKey: string
  initialAiBaseUrl: string
  initialAiModelName: string
  initialAiAutoClassifyOnScan: boolean
  initialAutoRerunEnabled: boolean
  initialRerunScheduleType: "simple" | "cron"
  initialRerunScheduleValue: string
  initialRetentionDays: number
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
  initialAiReviewEnabled,
  initialAiApiKey,
  initialAiBaseUrl,
  initialAiModelName,
  initialAiAutoClassifyOnScan,
  initialAutoRerunEnabled,
  initialRerunScheduleType,
  initialRerunScheduleValue,
  initialRetentionDays,
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
    aiReviewEnabled: Boolean(initialAiReviewEnabled),
    aiApiKey: initialAiApiKey ?? "",
    aiBaseUrl: initialAiBaseUrl ?? "https://api.openai.com/v1",
    aiModelName: initialAiModelName ?? "gpt-4o-mini",
    aiAutoClassifyOnScan: Boolean(initialAiAutoClassifyOnScan),
    autoRerunEnabled: Boolean(initialAutoRerunEnabled),
    rerunScheduleType: initialRerunScheduleType ?? "simple",
    rerunScheduleValue: initialRerunScheduleValue ?? "02:00",
    retentionDays: initialRetentionDays ?? 7,
  }

  const [values, setValues] = useState(normalizedInitial)
  const [error, setError] = useState<string | null>(null)
  const [saved, setSaved] = useState(false)
  const [isPending, startTransition] = useTransition()
  const router = useRouter()

  const isDirty =
    values.scanConcurrency !== normalizedInitial.scanConcurrency ||
    serialiseRulesets(values.rulesets) !== serialiseRulesets(normalizedInitial.rulesets) ||
    values.aiReviewEnabled !== normalizedInitial.aiReviewEnabled ||
    values.aiApiKey !== normalizedInitial.aiApiKey ||
    values.aiBaseUrl !== normalizedInitial.aiBaseUrl ||
    values.aiModelName !== normalizedInitial.aiModelName ||
    values.aiAutoClassifyOnScan !== normalizedInitial.aiAutoClassifyOnScan ||
    values.autoRerunEnabled !== normalizedInitial.autoRerunEnabled ||
    values.rerunScheduleType !== normalizedInitial.rerunScheduleType ||
    values.rerunScheduleValue !== normalizedInitial.rerunScheduleValue ||
    values.retentionDays !== normalizedInitial.retentionDays

  function handleSave() {
    setError(null)

    if (values.rulesets.length === 0) {
      setError("At least one ruleset must be selected.")
      return
    }

    if (values.aiReviewEnabled) {
      if (!values.aiApiKey) {
        setError("AI API Key is required when AI review is enabled.")
        return
      }
      if (!values.aiBaseUrl.trim()) {
        setError("AI Base URL is required when AI review is enabled.")
        return
      }
      if (!values.aiModelName.trim()) {
        setError("AI Model Name is required when AI review is enabled.")
        return
      }
    }

    startTransition(async () => {
      const { saveToolSettings } = await import("@/lib/client/settings-api")
      const result = await saveToolSettings({
        tool: "codeScanning",
        enabled: true,
        settings: {
          scanConcurrency: values.scanConcurrency,
          rulesets: serialiseRulesets([...values.rulesets, ...AUTO_RULESETS]),
          aiReviewEnabled: values.aiReviewEnabled ? "true" : "false",
          aiApiKey: values.aiApiKey,
          aiBaseUrl: values.aiBaseUrl,
          aiModelName: values.aiModelName,
          aiAutoClassifyOnScan: values.aiAutoClassifyOnScan ? "true" : "false",
          autoRerunEnabled: values.autoRerunEnabled ? "true" : "false",
          rerunScheduleType: values.rerunScheduleType,
          rerunScheduleValue: values.rerunScheduleValue,
          retentionDays: String(values.retentionDays),
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
        <div className="rounded-lg border border-amber-200 bg-amber-50 px-4 py-2.5 text-xs text-amber-700 dark:border-amber-900/30 dark:bg-amber-900/10 dark:text-amber-400">
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
      <fieldset disabled={!canEdit} className="space-y-3 disabled:opacity-50 disabled:grayscale-[0.5]">
        <RulesetPicker
          selected={values.rulesets}
          onChange={(rulesets) => setValues({ ...values, rulesets })}
          disabled={!canEdit}
        />
      </fieldset>
      {languageSupport && <div className="mt-4">{languageSupport}</div>}
      </SettingsCard>

      <SettingsCard eyebrow="Scanner Config" title="Scanner Settings">
      <fieldset disabled={!canEdit} className="space-y-4 disabled:opacity-50 disabled:grayscale-[0.5]">
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

          <div>
            <label className="mb-1.5 block text-xs font-medium text-[var(--color-text-primary)]">Data retention (days)</label>
            <input
              type="number"
              min={1}
              max={90}
              value={values.retentionDays}
              onChange={(e) => setValues({ ...values, retentionDays: Math.min(90, Math.max(1, parseInt(e.target.value) || 7)) })}
              className="w-full rounded-lg border border-[var(--color-border)] bg-[var(--color-surface)] px-3 py-2 text-sm text-[var(--color-text-primary)] focus:outline-none focus:ring-2 focus:ring-[var(--color-accent)]/30"
            />
            <p className="mt-1.5 text-xs text-[var(--color-text-secondary)]">Scan output stored in object storage for debugging and audit (1–90).</p>
          </div>
      </fieldset>
      </SettingsCard>

      <SettingsCard eyebrow="AI Review" title="AI Review Assistant">
      <fieldset disabled={!canEdit} className="space-y-4 disabled:opacity-50 disabled:grayscale-[0.5]">
          <label className="flex items-start gap-3 rounded-lg border border-[var(--color-border)] bg-[var(--color-surface)] px-3 py-3 text-sm">
            <input
              type="checkbox"
              checked={values.aiReviewEnabled}
              onChange={(e) => setValues({ ...values, aiReviewEnabled: e.target.checked })}
              className="mt-0.5 h-4 w-4 rounded border-[var(--color-border)] text-[var(--color-accent)] focus:ring-[var(--color-accent)]/30"
            />
            <span>
              <span className="block font-medium text-[var(--color-text-primary)]">Enable AI assessment</span>
              <span className="mt-1 block text-xs text-[var(--color-text-secondary)]">
                Allow reviewers to request AI assessments for findings.
              </span>
            </span>
          </label>

          {values.aiReviewEnabled && (
            <div className="space-y-4 rounded-lg border border-[var(--color-border)] p-4">
              <div>
                <label className="mb-1.5 block text-xs font-medium text-[var(--color-text-primary)]">
                  API Key
                </label>
                <input
                  type="password"
                  value={values.aiApiKey}
                  onChange={(e) => setValues({ ...values, aiApiKey: e.target.value })}
                  placeholder={normalizedInitial.aiApiKey ? "••••••••••••••••" : "Enter API key"}
                  className="w-full rounded-lg border border-[var(--color-border)] bg-[var(--color-surface)] px-3 py-2 text-sm text-[var(--color-text-primary)] focus:outline-none focus:ring-2 focus:ring-[var(--color-accent)]/30"
                />
              </div>

              <div>
                <label className="mb-1.5 block text-xs font-medium text-[var(--color-text-primary)]">
                  Base URL
                </label>
                <input
                  type="text"
                  value={values.aiBaseUrl}
                  onChange={(e) => setValues({ ...values, aiBaseUrl: e.target.value })}
                  className="w-full rounded-lg border border-[var(--color-border)] bg-[var(--color-surface)] px-3 py-2 text-sm text-[var(--color-text-primary)] focus:outline-none focus:ring-2 focus:ring-[var(--color-accent)]/30"
                />
              </div>

              <div>
                <label className="mb-1.5 block text-xs font-medium text-[var(--color-text-primary)]">
                  Model Name
                </label>
                <input
                  type="text"
                  value={values.aiModelName}
                  onChange={(e) => setValues({ ...values, aiModelName: e.target.value })}
                  className="w-full rounded-lg border border-[var(--color-border)] bg-[var(--color-surface)] px-3 py-2 text-sm text-[var(--color-text-primary)] focus:outline-none focus:ring-2 focus:ring-[var(--color-accent)]/30"
                />
              </div>

              <div className="border-t border-[var(--color-border)] pt-4">
                <label className="flex items-start gap-3 rounded-lg border border-[var(--color-border)] bg-[var(--color-surface)] px-3 py-3 text-sm">
                  <input
                    type="checkbox"
                    checked={values.aiAutoClassifyOnScan}
                    onChange={(e) => setValues({ ...values, aiAutoClassifyOnScan: e.target.checked })}
                    className="mt-0.5 h-4 w-4 rounded border-[var(--color-border)] text-[var(--color-accent)] focus:ring-[var(--color-accent)]/30"
                  />
                  <span>
                    <span className="block font-medium text-[var(--color-text-primary)]">Auto-classify findings after each scan</span>
                    <span className="mt-1 block text-xs text-[var(--color-text-secondary)]">
                      Automatically run AI review on all open findings immediately after each scan completes. Only findings without an existing review are processed.
                    </span>
                  </span>
                </label>
              </div>
            </div>
          )}
      </fieldset>
      </SettingsCard>

      <SettingsCard eyebrow="Automation" title="Scheduled Scans">
      <fieldset disabled={!canEdit} className="space-y-4 disabled:opacity-50 disabled:grayscale-[0.5]">
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
        <div className="rounded-lg border border-red-200 bg-red-50 px-3 py-2.5 text-sm text-red-700 dark:border-red-800 dark:bg-red-900/30 dark:text-red-400">
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
