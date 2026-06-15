"use client"

import { useEffect, useRef, useState, useTransition } from "react"
import { useRouter } from "next/navigation"
import { PrerequisitePanel } from "../PrerequisitePanel"
import { useSaveBarSection } from "../save-bar/SaveBarProvider"
import type { PrerequisiteItem } from "@/lib/shared/prerequisite-utils"
import { AdvisorySourcesCopyBar } from "@/components/settings/AdvisorySourcesCopyBar"
import { SettingsCard } from "@/components/shared/SettingsCard"
import { Input } from "@/components/ui/Input"
import { AdvisorySourcesGrid } from "../_components/AdvisorySourcesGrid"

interface DependenciesSetupFormProps {
  initialAutoRerunEnabled: boolean
  initialRerunScheduleType: "simple" | "cron"
  initialRerunScheduleValue: string
  initialScanConcurrency: string
  prereqItems: PrerequisiteItem[]
  prereqRefreshing: boolean
  refreshPrereqs: () => void
  canEnable: boolean
  passingCount: number
  totalCount: number
  canEdit?: boolean
  initialNvdEnabled: boolean
  initialNvdApiKey: string
  initialNvdApiKeyHint: string
  initialGhsaEnabled: boolean
  initialGhsaApiKey: string
  initialGhsaApiKeyHint: string
  initialArgusEnabled: boolean
  initialArgusApiKey: string
  initialArgusApiKeyHint: string
  containerHasAdvisory?: boolean
  containerAdvisoryConfig?: { nvdEnabled: boolean; ghsaEnabled: boolean }
  onCopyAdvisory?: () => Promise<void>
}

export function DependenciesSetupForm({
  initialAutoRerunEnabled,
  initialRerunScheduleType,
  initialRerunScheduleValue,
  initialScanConcurrency,
  prereqItems,
  prereqRefreshing,
  refreshPrereqs,
  canEnable,
  passingCount,
  totalCount,
  canEdit = true,
  initialNvdEnabled,
  initialNvdApiKey,
  initialNvdApiKeyHint,
  initialGhsaEnabled,
  initialGhsaApiKey,
  initialGhsaApiKeyHint,
  initialArgusEnabled,
  initialArgusApiKey,
  initialArgusApiKeyHint,
  containerHasAdvisory,
  containerAdvisoryConfig,
  onCopyAdvisory,
}: DependenciesSetupFormProps) {
  const [autoRerunEnabled, setAutoRerunEnabled] = useState(initialAutoRerunEnabled ?? false)
  const [rerunScheduleType, setRerunScheduleType] = useState<"simple" | "cron">(initialRerunScheduleType)
  const [rerunScheduleValue, setRerunScheduleValue] = useState(initialRerunScheduleValue)
  const [scanConcurrency, setScanConcurrency] = useState(initialScanConcurrency || "4")
  const [nvdEnabled, setNvdEnabled] = useState(initialNvdEnabled)
  const [nvdApiKey, setNvdApiKey] = useState(initialNvdApiKey)
  const [showNvdKey, setShowNvdKey] = useState(false)
  const [editingNvdKey, setEditingNvdKey] = useState(!initialNvdApiKey)
  const [ghsaEnabled, setGhsaEnabled] = useState(initialGhsaEnabled)
  const [ghsaApiKey, setGhsaApiKey] = useState(initialGhsaApiKey)
  const [showGhsaKey, setShowGhsaKey] = useState(false)
  const [editingGhsaKey, setEditingGhsaKey] = useState(!initialGhsaApiKey)
  const [argusEnabled, setArgusEnabled] = useState(initialArgusEnabled)
  const [argusApiKey, setArgusApiKey] = useState(initialArgusApiKey)
  const [showArgusKey, setShowArgusKey] = useState(false)
  const [editingArgusKey, setEditingArgusKey] = useState(!initialArgusApiKey)
  const [error, setError] = useState<string | null>(null)
  const [saved, setSaved] = useState(false)
  const [isPending, startTransition] = useTransition()
  const router = useRouter()
  const errorRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (error) errorRef.current?.scrollIntoView({ behavior: "smooth", block: "nearest" })
  }, [error])

  const isDirty =
    autoRerunEnabled !== initialAutoRerunEnabled ||
    rerunScheduleType !== initialRerunScheduleType ||
    rerunScheduleValue !== initialRerunScheduleValue ||
    scanConcurrency !== initialScanConcurrency ||
    nvdEnabled !== initialNvdEnabled ||
    nvdApiKey !== initialNvdApiKey ||
    ghsaEnabled !== initialGhsaEnabled ||
    ghsaApiKey !== initialGhsaApiKey ||
    argusEnabled !== initialArgusEnabled ||
    argusApiKey !== initialArgusApiKey

  function handleSave() {
    setError(null)

    if (ghsaEnabled && !ghsaApiKey.trim() && editingGhsaKey) {
      setError("GitHub PAT is required when GitHub Advisory Database is enabled.")
      return
    }

    if (argusEnabled && !argusApiKey.trim() && editingArgusKey) {
      setError("API key is required when Blu3Raven Argus is enabled.")
      return
    }

    startTransition(async () => {
      const { saveToolSettings } = await import("@/lib/client/settings-api")
      const result = await saveToolSettings({
        tool: "dependencies",
        enabled: true,
        settings: {
          autoRerunEnabled: autoRerunEnabled ? "true" : "false",
          rerunScheduleType,
          rerunScheduleValue,
          concurrency: scanConcurrency,
          nvdEnabled: nvdEnabled ? "true" : "false",
          nvdApiKey: editingNvdKey ? nvdApiKey : initialNvdApiKey,
          ghsaEnabled: ghsaEnabled ? "true" : "false",
          ghsaApiKey: editingGhsaKey ? ghsaApiKey : initialGhsaApiKey,
          argusEnabled: argusEnabled ? "true" : "false",
          argusApiKey: editingArgusKey ? argusApiKey : initialArgusApiKey,
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
    setAutoRerunEnabled(initialAutoRerunEnabled)
    setRerunScheduleType(initialRerunScheduleType)
    setRerunScheduleValue(initialRerunScheduleValue)
    setScanConcurrency(initialScanConcurrency)
    setNvdEnabled(initialNvdEnabled)
    setNvdApiKey(initialNvdApiKey)
    setEditingNvdKey(!initialNvdApiKey)
    setShowNvdKey(false)
    setGhsaEnabled(initialGhsaEnabled)
    setGhsaApiKey(initialGhsaApiKey)
    setEditingGhsaKey(!initialGhsaApiKey)
    setShowGhsaKey(false)
    setArgusEnabled(initialArgusEnabled)
    setArgusApiKey(initialArgusApiKey)
    setEditingArgusKey(!initialArgusApiKey)
    setShowArgusKey(false)
    setError(null)
    setSaved(false)
  }

  useSaveBarSection({
    id: "dependencies-setup",
    dirty: isDirty,
    saving: isPending,
    onSave: handleSave,
    onDiscard: handleDiscard,
  })

  // Status determination
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

      <SettingsCard eyebrow="Advisory Sources" title="Vulnerability Data Sources" subtitle="Configure external sources for vulnerability details, CVSS scores, and fix information.">
      <fieldset disabled={!canEdit} className="space-y-4 disabled:opacity-50">

        {containerHasAdvisory && !nvdApiKey && !ghsaApiKey && !argusApiKey && onCopyAdvisory && (
          <AdvisorySourcesCopyBar sourceLabel="Container" onCopy={async () => {
            await onCopyAdvisory()
            if (containerAdvisoryConfig) {
              setNvdEnabled(containerAdvisoryConfig.nvdEnabled)
              if (containerAdvisoryConfig.nvdEnabled) {
                setEditingNvdKey(false)
                setNvdApiKey("[redacted]")
              }
              setGhsaEnabled(containerAdvisoryConfig.ghsaEnabled)
              if (containerAdvisoryConfig.ghsaEnabled) {
                setEditingGhsaKey(false)
                setGhsaApiKey("[redacted]")
              }
            }
          }} />
        )}

        <AdvisorySourcesGrid
          canEdit={canEdit}
          values={{
            nvd: { enabled: nvdEnabled, apiKey: nvdApiKey, initialApiKey: initialNvdApiKey, initialApiKeyHint: initialNvdApiKeyHint, showKey: showNvdKey, editingKey: editingNvdKey },
            ghsa: { enabled: ghsaEnabled, apiKey: ghsaApiKey, initialApiKey: initialGhsaApiKey, initialApiKeyHint: initialGhsaApiKeyHint, showKey: showGhsaKey, editingKey: editingGhsaKey },
            argus: { enabled: argusEnabled, apiKey: argusApiKey, initialApiKey: initialArgusApiKey, initialApiKeyHint: initialArgusApiKeyHint, showKey: showArgusKey, editingKey: editingArgusKey },
          }}
          onChange={{
            nvd: { setEnabled: setNvdEnabled, setApiKey: setNvdApiKey, setShowKey: setShowNvdKey, setEditingKey: setEditingNvdKey },
            ghsa: { setEnabled: setGhsaEnabled, setApiKey: setGhsaApiKey, setShowKey: setShowGhsaKey, setEditingKey: setEditingGhsaKey },
            argus: { setEnabled: setArgusEnabled, setApiKey: setArgusApiKey, setShowKey: setShowArgusKey, setEditingKey: setEditingArgusKey },
          }}
        />
      </fieldset>
      </SettingsCard>

      <SettingsCard eyebrow="Scanner Config" title="Scanner Settings">
      <fieldset disabled={!canEdit} className="space-y-4 disabled:opacity-50">
          <div>
            <label className="mb-1.5 block text-xs font-medium text-[var(--color-text-primary)]">Scan concurrency</label>
            <Input
              type="number"
              min="1"
              value={scanConcurrency}
              onChange={(e) => setScanConcurrency(e.target.value)}
            />
            <p className="mt-1.5 text-xs text-[var(--color-text-secondary)]">Maximum repositories scanned in parallel.</p>
          </div>

      </fieldset>
      </SettingsCard>

      <SettingsCard eyebrow="Automation" title="Scheduled Scans">
      <fieldset disabled={!canEdit} className="space-y-4 disabled:opacity-50">
          <div className="space-y-4">
            <label className="flex items-start gap-3 rounded-lg border border-[var(--color-border)] bg-[var(--color-surface)] px-3 py-3 text-sm">
              <input
                type="checkbox"
                checked={autoRerunEnabled}
                onChange={(e) => setAutoRerunEnabled(e.target.checked)}
                className="mt-0.5 h-4 w-4 rounded border-[var(--color-border)] text-[var(--color-accent)] focus:ring-[var(--color-accent)]/30"
              />
              <span>
                <span className="block font-medium text-[var(--color-text-primary)]">Enable daily auto-rerun</span>
                <span className="mt-1 block text-xs text-[var(--color-text-secondary)]">
                  Automatically trigger a full scan of all selected organizations once per day.
                </span>
              </span>
            </label>

            {autoRerunEnabled && (
              <div className="space-y-4 rounded-lg border border-[var(--color-border)] p-4">
                <div className="flex flex-col gap-4 sm:flex-row sm:items-center">
                  {rerunScheduleType === "simple" ? (
                    <div className="flex-1">
                      <label className="mb-1.5 block text-xs font-medium text-[var(--color-text-primary)]">
                        Scan Time (Daily)
                      </label>
                      <Input
                        type="time"
                        value={rerunScheduleValue}
                        onChange={(e) => setRerunScheduleValue(e.target.value)}
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
                        value={rerunScheduleValue}
                        onChange={(e) => setRerunScheduleValue(e.target.value)}
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
                      checked={rerunScheduleType === "cron"}
                      onChange={(e) => {
                        const isCron = e.target.checked
                        setRerunScheduleType(isCron ? "cron" : "simple")
                        if (isCron) {
                          setRerunScheduleValue("0 2 * * *")
                        } else {
                          setRerunScheduleValue("02:00")
                        }
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
        <div ref={errorRef} className="rounded-lg border border-[var(--color-severity-critical-border)] bg-[var(--color-severity-critical-subtle)] px-3 py-2.5 text-sm text-[var(--color-severity-critical)]">
          {error}
        </div>
      )}

    </div>
  )
}
