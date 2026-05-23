"use client"

import { useEffect, useRef, useState, useTransition } from "react"
import { AdvisorySourcesCopyBar } from "@/components/settings/AdvisorySourcesCopyBar"
import { SettingsCard } from "@/components/shared/SettingsCard"
import { RetentionField } from "@/components/settings/RetentionField"
import { useLicense } from "@/lib/client/license/client"
import Link from "next/link"
import { useRouter } from "next/navigation"
import { PrerequisitePanel } from "../PrerequisitePanel"
import { SaveBar } from "../SaveBar"
import type { PrerequisiteItem } from "@/lib/shared/prerequisite-utils"

interface ContainerScanningSetupFormProps {
  initialAutoRerunEnabled: boolean
  initialRerunScheduleType: "simple" | "cron"
  initialRerunScheduleValue: string
  initialScanConcurrency: string
  initialRetentionDays: number
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
  scaHasAdvisory?: boolean
  scaAdvisoryConfig?: { nvdEnabled: boolean; ghsaEnabled: boolean }
  onCopyAdvisory?: () => Promise<void>
}

export function ContainerScanningSetupForm({
  initialAutoRerunEnabled,
  initialRerunScheduleType,
  initialRerunScheduleValue,
  initialScanConcurrency,
  initialRetentionDays,
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
  scaHasAdvisory,
  scaAdvisoryConfig,
  onCopyAdvisory,
}: ContainerScanningSetupFormProps) {

  function maskKey(key: string, hint?: string): string {
    if (!key) return ""
    if (key === "[redacted]") return "\u2022".repeat(8) + (hint || "")
    if (key.length <= 4) return "\u2022".repeat(8)
    return "\u2022".repeat(8) + key.slice(-4)
  }

  const { addons } = useLicense()
  const hasArgusLicense = addons?.includes("argus") ?? false

  const [autoRerunEnabled, setAutoRerunEnabled] = useState(initialAutoRerunEnabled ?? false)
  const [rerunScheduleType, setRerunScheduleType] = useState<"simple" | "cron">(initialRerunScheduleType)
  const [rerunScheduleValue, setRerunScheduleValue] = useState(initialRerunScheduleValue)
  const [scanConcurrency, setScanConcurrency] = useState(initialScanConcurrency || "4")
  const [retentionDays, setRetentionDays] = useState(initialRetentionDays ?? 7)
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
    retentionDays !== (initialRetentionDays ?? 7) ||
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
        tool: "containerScanning",
        enabled: true,
        settings: {
          autoRerunEnabled: autoRerunEnabled ? "true" : "false",
          rerunScheduleType,
          rerunScheduleValue,
          concurrency: scanConcurrency,
          retentionDays: String(retentionDays),
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
    setRetentionDays(initialRetentionDays ?? 7)
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

      <SettingsCard eyebrow="Advisory Sources" title="Vulnerability Data Sources" subtitle="Configure external sources for vulnerability details, CVSS scores, and fix information.">
      <fieldset disabled={!canEdit} className="space-y-4 disabled:opacity-50 disabled:grayscale-[0.5]">

        {scaHasAdvisory && !nvdApiKey && !ghsaApiKey && !argusApiKey && onCopyAdvisory && (
          <AdvisorySourcesCopyBar sourceLabel="Dependencies" onCopy={async () => {
            await onCopyAdvisory()
            if (scaAdvisoryConfig) {
              setNvdEnabled(scaAdvisoryConfig.nvdEnabled)
              if (scaAdvisoryConfig.nvdEnabled) {
                setEditingNvdKey(false)
                setNvdApiKey("[redacted]")
              }
              setGhsaEnabled(scaAdvisoryConfig.ghsaEnabled)
              if (scaAdvisoryConfig.ghsaEnabled) {
                setEditingGhsaKey(false)
                setGhsaApiKey("[redacted]")
              }
            }
          }} />
        )}

        <div className="grid grid-cols-1 gap-6 md:grid-cols-2 lg:grid-cols-3">
          {/* NVD card */}
          <div className={`relative space-y-3 rounded-lg border p-4 transition-colors ${
            nvdEnabled
              ? "border-[var(--color-accent)]/40 bg-[var(--color-accent)]/[0.03]"
              : "border-[var(--color-border)] bg-[var(--color-surface)]"
          }`}>
            <div className="flex items-start justify-between">
              <label className="flex items-center gap-2.5 text-sm">
                <input
                  type="checkbox"
                  checked={nvdEnabled}
                  onChange={(e) => setNvdEnabled(e.target.checked)}
                  className="h-4 w-4 rounded border-[var(--color-border)] text-[var(--color-accent)] focus:ring-[var(--color-accent)]/30"
                />
                <div>
                  <span className="font-medium text-[var(--color-text-primary)]">NVD (NIST)</span>
                  <p className="text-xs text-[var(--color-text-secondary)]">National Vulnerability Database</p>
                </div>
              </label>
              {nvdEnabled && (
                <span className="inline-flex shrink-0 items-center gap-1 whitespace-nowrap rounded-full bg-emerald-100 px-2 py-0.5 text-[10px] font-medium text-emerald-700 dark:bg-emerald-900/30 dark:text-emerald-400">
                  <svg className="h-2.5 w-2.5" viewBox="0 0 6 6" fill="currentColor"><circle cx="3" cy="3" r="3" /></svg>
                  Active
                </span>
              )}
            </div>
            <div className={`space-y-3 transition-opacity ${nvdEnabled ? "" : "opacity-40 pointer-events-none"}`}>
              <div>
                <label className="mb-1.5 block text-xs font-medium text-[var(--color-text-primary)]">
                  API Key <span className="font-normal text-[var(--color-text-tertiary)]">(optional)</span>
                </label>
                {!editingNvdKey ? (
                  <div className="flex items-center gap-2">
                    <input
                      type="text"
                      value={maskKey(initialNvdApiKey, initialNvdApiKeyHint)}
                      readOnly
                      className="min-w-0 flex-1 rounded-lg border border-[var(--color-border)] bg-[var(--color-surface-raised)] px-3 py-2 font-mono text-sm text-[var(--color-text-secondary)] outline-none"
                    />
                    {canEdit && (
                      <button
                        type="button"
                        onClick={() => { setEditingNvdKey(true); setNvdApiKey(""); setShowNvdKey(false) }}
                        className="shrink-0 rounded-lg border border-[var(--color-border)] px-3 py-2 text-xs font-medium text-[var(--color-text-secondary)] transition-colors hover:bg-[var(--color-surface-raised)] hover:text-[var(--color-text-primary)]"
                      >
                        Change
                      </button>
                    )}
                  </div>
                ) : (
                  <div className="relative">
                    <input
                      type={showNvdKey ? "text" : "password"}
                      value={nvdApiKey}
                      onChange={(e) => setNvdApiKey(e.target.value)}
                      placeholder="Enter NVD API key"
                      className="w-full rounded-lg border border-[var(--color-border)] bg-[var(--color-surface)] px-3 py-2 pr-10 text-sm text-[var(--color-text-primary)] placeholder:text-[var(--color-text-tertiary)] focus:border-[var(--color-accent)]/50 focus:outline-none focus:ring-2 focus:ring-[var(--color-accent)]/20"
                    />
                    <button
                      type="button"
                      onClick={() => setShowNvdKey(!showNvdKey)}
                      className="absolute right-2 top-1/2 -translate-y-1/2 rounded p-0.5 text-[var(--color-text-tertiary)] transition-colors hover:text-[var(--color-text-primary)]"
                      aria-label={showNvdKey ? "Hide key" : "Show key"}
                    >
                      <svg className="h-4 w-4" viewBox="0 0 20 20" fill="currentColor">
                        {showNvdKey ? (
                          <>
                            <path d="M3.707 2.293a1 1 0 00-1.414 1.414l14 14a1 1 0 001.414-1.414l-1.473-1.473A10.014 10.014 0 0019.542 10C18.268 5.943 14.478 3 10 3a9.958 9.958 0 00-4.512 1.074l-1.78-1.781zm4.261 4.26l1.514 1.515a2.003 2.003 0 012.45 2.45l1.514 1.514a4 4 0 00-5.478-5.478z" />
                            <path d="M12.454 16.697L9.75 13.992a4 4 0 01-3.742-3.741L2.335 6.578A9.98 9.98 0 00.458 10c1.274 4.057 5.065 7 9.542 7 .847 0 1.669-.105 2.454-.303z" />
                          </>
                        ) : (
                          <>
                            <path d="M10 12a2 2 0 100-4 2 2 0 000 4z" />
                            <path fillRule="evenodd" d="M.458 10C1.732 5.943 5.522 3 10 3s8.268 2.943 9.542 7c-1.274 4.057-5.064 7-9.542 7S1.732 14.057.458 10zM14 10a4 4 0 11-8 0 4 4 0 018 0z" clipRule="evenodd" />
                          </>
                        )}
                      </svg>
                    </button>
                  </div>
                )}
              </div>

              <div className="flex items-start gap-2 rounded-md border border-[var(--color-border)]/60 bg-[var(--color-bg-secondary)] px-3 py-2.5">
                <svg className="mt-0.5 h-3.5 w-3.5 shrink-0 text-[var(--color-text-tertiary)]" viewBox="0 0 16 16" fill="currentColor">
                  <path fillRule="evenodd" d="M15 8A7 7 0 111 8a7 7 0 0114 0zm-6 3.5a1 1 0 11-2 0 1 1 0 012 0zM8 5.5a1 1 0 00-.993.884L7 6.5v3a1 1 0 001.993.117L9 9.5v-3A1 1 0 008 5.5z" clipRule="evenodd" />
                </svg>
                <div className="text-xs text-[var(--color-text-secondary)]">
                  <p className="font-medium text-[var(--color-text-primary)]">How to get a key</p>
                  <ol className="mt-1 list-inside list-decimal space-y-0.5 leading-relaxed">
                    <li>Visit <a href="https://nvd.nist.gov/developers/request-an-api-key" target="_blank" rel="noopener noreferrer" className="text-[var(--color-accent)] hover:underline">nvd.nist.gov &rsaquo; Request API Key</a></li>
                    <li>Enter your email and organization name</li>
                    <li>Check your inbox and paste the key above</li>
                  </ol>
                  <div className="mt-2 flex items-center gap-3 border-t border-[var(--color-border)]/40 pt-2 text-[var(--color-text-tertiary)]">
                    <span className="flex items-center gap-1">
                      <svg className="h-3 w-3" viewBox="0 0 16 16" fill="currentColor"><path d="M8 1.5a6.5 6.5 0 100 13 6.5 6.5 0 000-13zM0 8a8 8 0 1116 0A8 8 0 010 8zm9-3a1 1 0 11-2 0 1 1 0 012 0zM8 6.5a.75.75 0 01.75.75v3.5a.75.75 0 01-1.5 0v-3.5A.75.75 0 018 6.5z" /></svg>
                      Without key: 5 req/30s
                    </span>
                    <span className="flex items-center gap-1">
                      <svg className="h-3 w-3 text-emerald-500" viewBox="0 0 16 16" fill="currentColor"><path fillRule="evenodd" d="M8 1.5a6.5 6.5 0 100 13 6.5 6.5 0 000-13zM0 8a8 8 0 1116 0A8 8 0 010 8zm11.28-1.72a.75.75 0 010 1.06l-4 4a.75.75 0 01-1.06 0l-2-2a.75.75 0 111.06-1.06L6.75 9.69l3.47-3.47a.75.75 0 011.06 0z" clipRule="evenodd" /></svg>
                      With key: 50 req/30s
                    </span>
                  </div>
                </div>
              </div>
            </div>
          </div>

          {/* GHSA card */}
          <div className={`relative space-y-3 rounded-lg border p-4 transition-colors ${
            ghsaEnabled
              ? (ghsaApiKey.trim() || (!editingGhsaKey && initialGhsaApiKey))
                ? "border-[var(--color-accent)]/40 bg-[var(--color-accent)]/[0.03]"
                : "border-amber-400/40 bg-amber-500/[0.03]"
              : "border-[var(--color-border)] bg-[var(--color-surface)]"
          }`}>
            <div className="flex items-start justify-between">
              <label className="flex items-center gap-2.5 text-sm">
                <input
                  type="checkbox"
                  checked={ghsaEnabled}
                  onChange={(e) => setGhsaEnabled(e.target.checked)}
                  className="h-4 w-4 rounded border-[var(--color-border)] text-[var(--color-accent)] focus:ring-[var(--color-accent)]/30"
                />
                <div>
                  <span className="font-medium text-[var(--color-text-primary)]">GitHub Advisory Database</span>
                  <p className="text-xs text-[var(--color-text-secondary)]">GHSA-enriched Vulnerability Database</p>
                </div>
              </label>
              {ghsaEnabled && (
                <span className={`inline-flex shrink-0 items-center gap-1 whitespace-nowrap rounded-full px-2 py-0.5 text-[10px] font-medium ${
                  (ghsaApiKey.trim() || (!editingGhsaKey && initialGhsaApiKey))
                    ? "bg-emerald-100 text-emerald-700 dark:bg-emerald-900/30 dark:text-emerald-400"
                    : "bg-amber-100 text-amber-700 dark:bg-amber-900/30 dark:text-amber-400"
                }`}>
                  <svg className="h-2.5 w-2.5" viewBox="0 0 6 6" fill="currentColor"><circle cx="3" cy="3" r="3" /></svg>
                  {(ghsaApiKey.trim() || (!editingGhsaKey && initialGhsaApiKey)) ? "Active" : "Needs key"}
                </span>
              )}
            </div>
            <div className={`space-y-3 transition-opacity ${ghsaEnabled ? "" : "opacity-40 pointer-events-none"}`}>
              <div>
                <label className="mb-1.5 block text-xs font-medium text-[var(--color-text-primary)]">
                  GitHub PAT <span className="font-normal text-amber-600 dark:text-amber-400">(required)</span>
                </label>
                {!editingGhsaKey ? (
                  <div className="flex items-center gap-2">
                    <input
                      type="text"
                      value={maskKey(initialGhsaApiKey, initialGhsaApiKeyHint)}
                      readOnly
                      className="min-w-0 flex-1 rounded-lg border border-[var(--color-border)] bg-[var(--color-surface-raised)] px-3 py-2 font-mono text-sm text-[var(--color-text-secondary)] outline-none"
                    />
                    {canEdit && (
                      <button
                        type="button"
                        onClick={() => { setEditingGhsaKey(true); setGhsaApiKey(""); setShowGhsaKey(false) }}
                        className="shrink-0 rounded-lg border border-[var(--color-border)] px-3 py-2 text-xs font-medium text-[var(--color-text-secondary)] transition-colors hover:bg-[var(--color-surface-raised)] hover:text-[var(--color-text-primary)]"
                      >
                        Change
                      </button>
                    )}
                  </div>
                ) : (
                  <>
                    <div className="relative">
                      <input
                        type={showGhsaKey ? "text" : "password"}
                        value={ghsaApiKey}
                        onChange={(e) => setGhsaApiKey(e.target.value)}
                        placeholder="ghp_..."
                        className={`w-full rounded-lg border bg-[var(--color-surface)] px-3 py-2 pr-10 text-sm text-[var(--color-text-primary)] placeholder:text-[var(--color-text-tertiary)] focus:outline-none focus:ring-2 ${
                          ghsaEnabled && !ghsaApiKey.trim()
                            ? "border-amber-400/60 focus:border-amber-400/60 focus:ring-amber-400/20"
                            : "border-[var(--color-border)] focus:border-[var(--color-accent)]/50 focus:ring-[var(--color-accent)]/20"
                        }`}
                      />
                      <button
                        type="button"
                        onClick={() => setShowGhsaKey(!showGhsaKey)}
                        className="absolute right-2 top-1/2 -translate-y-1/2 rounded p-0.5 text-[var(--color-text-tertiary)] transition-colors hover:text-[var(--color-text-primary)]"
                        aria-label={showGhsaKey ? "Hide key" : "Show key"}
                      >
                        <svg className="h-4 w-4" viewBox="0 0 20 20" fill="currentColor">
                          {showGhsaKey ? (
                            <>
                              <path d="M3.707 2.293a1 1 0 00-1.414 1.414l14 14a1 1 0 001.414-1.414l-1.473-1.473A10.014 10.014 0 0019.542 10C18.268 5.943 14.478 3 10 3a9.958 9.958 0 00-4.512 1.074l-1.78-1.781zm4.261 4.26l1.514 1.515a2.003 2.003 0 012.45 2.45l1.514 1.514a4 4 0 00-5.478-5.478z" />
                              <path d="M12.454 16.697L9.75 13.992a4 4 0 01-3.742-3.741L2.335 6.578A9.98 9.98 0 00.458 10c1.274 4.057 5.065 7 9.542 7 .847 0 1.669-.105 2.454-.303z" />
                            </>
                          ) : (
                            <>
                              <path d="M10 12a2 2 0 100-4 2 2 0 000 4z" />
                              <path fillRule="evenodd" d="M.458 10C1.732 5.943 5.522 3 10 3s8.268 2.943 9.542 7c-1.274 4.057-5.064 7-9.542 7S1.732 14.057.458 10zM14 10a4 4 0 11-8 0 4 4 0 018 0z" clipRule="evenodd" />
                            </>
                          )}
                        </svg>
                      </button>
                    </div>
                    {ghsaEnabled && !ghsaApiKey.trim() && (
                      <p className="mt-1.5 flex items-center gap-1 text-xs text-amber-600 dark:text-amber-400">
                        <svg className="h-3 w-3 shrink-0" viewBox="0 0 16 16" fill="currentColor">
                          <path fillRule="evenodd" d="M8.22 1.754a.25.25 0 00-.44 0L1.698 13.132a.25.25 0 00.22.368h12.164a.25.25 0 00.22-.368L8.22 1.754zm-1.763-.707c.659-1.234 2.427-1.234 3.086 0l6.082 11.378A1.75 1.75 0 0114.082 15H1.918a1.75 1.75 0 01-1.543-2.575L6.457 1.047zM9 11a1 1 0 11-2 0 1 1 0 012 0zm-.25-5.25a.75.75 0 00-1.5 0v2.5a.75.75 0 001.5 0v-2.5z" clipRule="evenodd" />
                        </svg>
                        A GitHub PAT is required to query the advisory database.
                      </p>
                    )}
                  </>
                )}
              </div>

              <div className="flex items-start gap-2 rounded-md border border-[var(--color-border)]/60 bg-[var(--color-bg-secondary)] px-3 py-2.5">
                <svg className="mt-0.5 h-3.5 w-3.5 shrink-0 text-[var(--color-text-tertiary)]" viewBox="0 0 16 16" fill="currentColor">
                  <path fillRule="evenodd" d="M15 8A7 7 0 111 8a7 7 0 0114 0zm-6 3.5a1 1 0 11-2 0 1 1 0 012 0zM8 5.5a1 1 0 00-.993.884L7 6.5v3a1 1 0 001.993.117L9 9.5v-3A1 1 0 008 5.5z" clipRule="evenodd" />
                </svg>
                <div className="text-xs text-[var(--color-text-secondary)]">
                  <p className="font-medium text-[var(--color-text-primary)]">How to create a PAT</p>
                  <ol className="mt-1 list-inside list-decimal space-y-0.5 leading-relaxed">
                    <li>Go to <a href="https://github.com/settings/tokens?type=beta" target="_blank" rel="noopener noreferrer" className="text-[var(--color-accent)] hover:underline">GitHub &rsaquo; Settings &rsaquo; Tokens</a> (fine-grained)</li>
                    <li>Click &quot;Generate new token&quot;</li>
                    <li>No extra permissions needed &mdash; advisory access is public</li>
                  </ol>
                  <p className="mt-1.5 text-[var(--color-text-tertiary)]">
                    A classic PAT with zero scopes also works.
                  </p>
                </div>
              </div>
            </div>
          </div>

          {/* Blu3Raven Argus card */}
          {!hasArgusLicense ? (
            <div className="relative space-y-3 rounded-lg border border-purple-500/15 bg-purple-500/[0.03] p-4">
              <div className="flex items-start justify-between">
                <div>
                  <div className="flex items-center gap-2">
                    <span className="font-medium text-[var(--color-text-primary)]">Blu3Raven Argus</span>
                    <span className="rounded-full bg-purple-500/10 px-2 py-0.5 text-[10px] font-semibold text-purple-500">Add-on</span>
                  </div>
                  <p className="mt-1 text-xs text-[var(--color-text-secondary)]">
                    AI-powered threat intelligence with EPSS scores, exploit availability, and advisory enrichment. Requires a Blu3Raven Argus license.
                  </p>
                </div>
                <Link
                  href="/settings/license"
                  className="shrink-0 rounded-lg border border-purple-500/20 px-3 py-1.5 text-xs font-semibold text-purple-500 transition-colors hover:bg-purple-500/5"
                >
                  Activate
                </Link>
              </div>
            </div>
          ) : (
          <div className={`relative space-y-3 rounded-lg border p-4 transition-colors ${
            argusEnabled
              ? (argusApiKey.trim() || (!editingArgusKey && initialArgusApiKey))
                ? "border-[var(--color-accent)]/40 bg-[var(--color-accent)]/[0.03]"
                : "border-amber-400/40 bg-amber-500/[0.03]"
              : "border-[var(--color-border)] bg-[var(--color-surface)]"
          }`}>
            <div className="flex items-start justify-between">
              <label className="flex items-center gap-2.5 text-sm">
                <input
                  type="checkbox"
                  checked={argusEnabled}
                  onChange={(e) => setArgusEnabled(e.target.checked)}
                  className="h-4 w-4 rounded border-[var(--color-border)] text-[var(--color-accent)] focus:ring-[var(--color-accent)]/30"
                />
                <div>
                  <span className="font-medium text-[var(--color-text-primary)]">Blu3Raven Argus</span>
                  <p className="text-xs text-[var(--color-text-secondary)]">AI-Powered Threat Intelligence</p>
                </div>
              </label>
              {argusEnabled && (
                <span className={`inline-flex shrink-0 items-center gap-1 whitespace-nowrap rounded-full px-2 py-0.5 text-[10px] font-medium ${
                  (argusApiKey.trim() || (!editingArgusKey && initialArgusApiKey))
                    ? "bg-emerald-100 text-emerald-700 dark:bg-emerald-900/30 dark:text-emerald-400"
                    : "bg-amber-100 text-amber-700 dark:bg-amber-900/30 dark:text-amber-400"
                }`}>
                  <svg className="h-2.5 w-2.5" viewBox="0 0 6 6" fill="currentColor"><circle cx="3" cy="3" r="3" /></svg>
                  {(argusApiKey.trim() || (!editingArgusKey && initialArgusApiKey)) ? "Active" : "Needs key"}
                </span>
              )}
            </div>
            <div className={`space-y-3 transition-opacity ${argusEnabled ? "" : "opacity-40 pointer-events-none"}`}>
              <div>
                <label className="mb-1.5 block text-xs font-medium text-[var(--color-text-primary)]">
                  API Key <span className="font-normal text-amber-600 dark:text-amber-400">(required)</span>
                </label>
                {!editingArgusKey ? (
                  <div className="flex items-center gap-2">
                    <input
                      type="text"
                      value={maskKey(initialArgusApiKey, initialArgusApiKeyHint)}
                      readOnly
                      className="min-w-0 flex-1 rounded-lg border border-[var(--color-border)] bg-[var(--color-surface-raised)] px-3 py-2 font-mono text-sm text-[var(--color-text-secondary)] outline-none"
                    />
                    {canEdit && (
                      <button
                        type="button"
                        onClick={() => { setEditingArgusKey(true); setArgusApiKey(""); setShowArgusKey(false) }}
                        className="shrink-0 rounded-lg border border-[var(--color-border)] px-3 py-2 text-xs font-medium text-[var(--color-text-secondary)] transition-colors hover:bg-[var(--color-surface-raised)] hover:text-[var(--color-text-primary)]"
                      >
                        Change
                      </button>
                    )}
                  </div>
                ) : (
                  <>
                    <div className="relative">
                      <input
                        type={showArgusKey ? "text" : "password"}
                        value={argusApiKey}
                        onChange={(e) => setArgusApiKey(e.target.value)}
                        placeholder="argus_..."
                        className={`w-full rounded-lg border bg-[var(--color-surface)] px-3 py-2 pr-10 text-sm text-[var(--color-text-primary)] placeholder:text-[var(--color-text-tertiary)] focus:outline-none focus:ring-2 ${
                          argusEnabled && !argusApiKey.trim()
                            ? "border-amber-400/60 focus:border-amber-400/60 focus:ring-amber-400/20"
                            : "border-[var(--color-border)] focus:border-[var(--color-accent)]/50 focus:ring-[var(--color-accent)]/20"
                        }`}
                      />
                      <button
                        type="button"
                        onClick={() => setShowArgusKey(!showArgusKey)}
                        className="absolute right-2 top-1/2 -translate-y-1/2 rounded p-0.5 text-[var(--color-text-tertiary)] transition-colors hover:text-[var(--color-text-primary)]"
                        aria-label={showArgusKey ? "Hide key" : "Show key"}
                      >
                        <svg className="h-4 w-4" viewBox="0 0 20 20" fill="currentColor">
                          {showArgusKey ? (
                            <>
                              <path d="M3.707 2.293a1 1 0 00-1.414 1.414l14 14a1 1 0 001.414-1.414l-1.473-1.473A10.014 10.014 0 0019.542 10C18.268 5.943 14.478 3 10 3a9.958 9.958 0 00-4.512 1.074l-1.78-1.781zm4.261 4.26l1.514 1.515a2.003 2.003 0 012.45 2.45l1.514 1.514a4 4 0 00-5.478-5.478z" />
                              <path d="M12.454 16.697L9.75 13.992a4 4 0 01-3.742-3.741L2.335 6.578A9.98 9.98 0 00.458 10c1.274 4.057 5.065 7 9.542 7 .847 0 1.669-.105 2.454-.303z" />
                            </>
                          ) : (
                            <>
                              <path d="M10 12a2 2 0 100-4 2 2 0 000 4z" />
                              <path fillRule="evenodd" d="M.458 10C1.732 5.943 5.522 3 10 3s8.268 2.943 9.542 7c-1.274 4.057-5.064 7-9.542 7S1.732 14.057.458 10zM14 10a4 4 0 11-8 0 4 4 0 018 0z" clipRule="evenodd" />
                            </>
                          )}
                        </svg>
                      </button>
                    </div>
                    {argusEnabled && !argusApiKey.trim() && (
                      <p className="mt-1.5 flex items-center gap-1 text-xs text-amber-600 dark:text-amber-400">
                        <svg className="h-3 w-3 shrink-0" viewBox="0 0 16 16" fill="currentColor">
                          <path fillRule="evenodd" d="M8.22 1.754a.25.25 0 00-.44 0L1.698 13.132a.25.25 0 00.22.368h12.164a.25.25 0 00.22-.368L8.22 1.754zm-1.763-.707c.659-1.234 2.427-1.234 3.086 0l6.082 11.378A1.75 1.75 0 0114.082 15H1.918a1.75 1.75 0 01-1.543-2.575L6.457 1.047zM9 11a1 1 0 11-2 0 1 1 0 012 0zm-.25-5.25a.75.75 0 00-1.5 0v2.5a.75.75 0 001.5 0v-2.5z" clipRule="evenodd" />
                        </svg>
                        An API key is required to use Argus enrichment.
                      </p>
                    )}
                  </>
                )}
              </div>

              <div className="flex items-start gap-2 rounded-md border border-[var(--color-border)]/60 bg-[var(--color-bg-secondary)] px-3 py-2.5">
                <svg className="mt-0.5 h-3.5 w-3.5 shrink-0 text-[var(--color-text-tertiary)]" viewBox="0 0 16 16" fill="currentColor">
                  <path fillRule="evenodd" d="M15 8A7 7 0 111 8a7 7 0 0114 0zm-6 3.5a1 1 0 11-2 0 1 1 0 012 0zM8 5.5a1 1 0 00-.993.884L7 6.5v3a1 1 0 001.993.117L9 9.5v-3A1 1 0 008 5.5z" clipRule="evenodd" />
                </svg>
                <div className="text-xs text-[var(--color-text-secondary)]">
                  <p className="font-medium text-[var(--color-text-primary)]">How to get an API key</p>
                  <p className="mt-1 leading-relaxed">
                    API key provisioning instructions coming soon. Contact your Blu3Raven representative for early access.
                  </p>
                </div>
              </div>
            </div>
          </div>
          )}
        </div>
      </fieldset>
      </SettingsCard>

      <SettingsCard eyebrow="Scanner Config" title="Scanner Settings">
      <fieldset disabled={!canEdit} className="space-y-4 disabled:opacity-50 disabled:grayscale-[0.5]">
          <div>
            <label className="mb-1.5 block text-xs font-medium text-[var(--color-text-primary)]">
              Scan concurrency
            </label>
            <input
              type="number"
              min="1"
              value={scanConcurrency}
              onChange={(e) => setScanConcurrency(e.target.value)}
              className="w-full rounded-lg border border-[var(--color-border)] bg-[var(--color-surface)] px-3 py-2 text-sm text-[var(--color-text-primary)] focus:outline-none focus:ring-2 focus:ring-[var(--color-accent)]/30"
            />
            <p className="mt-1.5 text-xs text-[var(--color-text-secondary)]">
              Maximum container images scanned in parallel.
            </p>
          </div>

          <div>
            <label className="mb-1.5 block text-xs font-medium text-[var(--color-text-primary)]">Data retention</label>
            <RetentionField value={retentionDays} onChange={setRetentionDays} />
          </div>
      </fieldset>
      </SettingsCard>

      <SettingsCard eyebrow="Automation" title="Scheduled Scans">
      <fieldset disabled={!canEdit} className="space-y-4 disabled:opacity-50 disabled:grayscale-[0.5]">
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
                      <input
                        type="time"
                        value={rerunScheduleValue}
                        onChange={(e) => setRerunScheduleValue(e.target.value)}
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
                        value={rerunScheduleValue}
                        onChange={(e) => setRerunScheduleValue(e.target.value)}
                        placeholder="e.g. 0 2 * * *"
                        className="w-full rounded-lg border border-[var(--color-border)] bg-[var(--color-surface)] px-3 py-2 text-sm text-[var(--color-text-primary)] focus:outline-none focus:ring-2 focus:ring-[var(--color-accent)]/30 font-mono"
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
        <div ref={errorRef} className="rounded-lg border border-red-200 bg-red-50 px-3 py-2.5 text-sm text-red-700 dark:border-red-800 dark:bg-red-900/30 dark:text-red-400">
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
