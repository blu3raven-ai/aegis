"use client"

import { useEffect, useState } from "react"
import {
  submitScan,
  getScanStatus,
  type ScanDetail,
} from "@/lib/client/repos-api"
import { scannerAbbrev } from "@/lib/shared/findings/row-mapper"
import { Button } from "@/components/ui/Button"

interface PreReleaseScanPanelProps {
  repoId: string
  onScanComplete: (scanId: string) => void
}


const STATUS_STYLES: Record<ScanDetail["status"], string> = {
  queued:    "text-[var(--color-state-pending)]",
  running:   "text-[var(--color-state-pending)]",
  completed: "text-[var(--color-status-ok)]",
  failed:    "text-[var(--color-severity-critical)]",
}

const SEV_CLASSES: Record<"critical" | "high" | "medium" | "low", string> = {
  critical: "text-[var(--color-severity-critical)]",
  high:     "text-[var(--color-severity-high)]",
  medium:   "text-[var(--color-severity-medium)]",
  low:      "text-[var(--color-severity-low)]",
}

const ALL_SCANNERS = ["dependencies", "code_scanning", "container_scanning", "secrets"] as const

function validateSha(value: string): string | null {
  if (!value.trim()) return "Commit SHA is required"
  if (!/^[0-9a-f]{7,64}$/.test(value.trim())) return "Must be 7–64 lowercase hex characters"
  return null
}

function shortenSha(sha: string): string {
  return sha.length > 7 ? sha.slice(0, 7) : sha
}

export function PreReleaseScanPanel({ repoId, onScanComplete }: PreReleaseScanPanelProps) {
  const [sha, setSha] = useState("")
  const [shaError, setShaError] = useState<string | null>(null)
  const [useAllScanners, setUseAllScanners] = useState(true)
  const [selectedScanners, setSelectedScanners] = useState<Set<string>>(
    new Set(["dependencies", "code_scanning", "container_scanning", "secrets"]),
  )
  const [submitting, setSubmitting] = useState(false)
  const [submitError, setSubmitError] = useState<string | null>(null)
  const [activeScan, setActiveScan] = useState<ScanDetail | null>(null)

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    const err = validateSha(sha)
    if (err) {
      setShaError(err)
      return
    }
    setShaError(null)
    setSubmitError(null)
    setSubmitting(true)
    try {
      const scanners = useAllScanners ? undefined : [...selectedScanners]
      const sub = await submitScan(repoId, sha.trim(), scanners)
      setActiveScan({
        scan_id: sub.scan_id,
        repo_id: sub.repo_id,
        commit_sha: sub.commit_sha,
        scanner_types: sub.scanner_types,
        status: sub.status as ScanDetail["status"],
        submitted_at: sub.submitted_at,
        submitted_by: sub.submitted_by,
        started_at: null,
        finished_at: null,
        finding_counts: null,
        error: null,
      })
      setSha("")
    } catch (err) {
      setSubmitError(err instanceof Error ? err.message : "Submission failed")
    } finally {
      setSubmitting(false)
    }
  }

  // Restart the poll whenever a new scan starts or it transitions to a terminal state.
  useEffect(() => {
    if (!activeScan) return
    if (activeScan.status === "completed" || activeScan.status === "failed") return

    const id = setInterval(async () => {
      try {
        const detail = await getScanStatus(activeScan.scan_id)
        setActiveScan(detail)
        if (detail.status === "completed" || detail.status === "failed") {
          clearInterval(id)
          if (detail.status === "completed") onScanComplete(detail.scan_id)
        }
      } catch {
        // Non-fatal — transient network errors should not stop polling.
      }
    }, 3_000)

    return () => clearInterval(id)
  }, [activeScan?.scan_id, activeScan?.status])

  const scanInFlight =
    activeScan?.status === "queued" || activeScan?.status === "running"
  const submitDisabled = submitting || scanInFlight

  function toggleScanner(key: string) {
    setSelectedScanners((prev) => {
      const next = new Set(prev)
      if (next.has(key)) next.delete(key)
      else next.add(key)
      return next
    })
  }

  return (
    <div className="flex flex-col gap-4">
      {/* Submission form */}
      <form
        onSubmit={handleSubmit}
        className="rounded-md border border-[var(--color-border)] bg-[var(--color-surface)] p-5"
      >
        <h2 className="mb-4 text-base font-semibold text-[var(--color-text-primary)]">
          Trigger pre-release scan
        </h2>

        <div className="mb-4">
          <label
            htmlFor="pre-release-scan-sha"
            className="mb-1.5 block text-xs font-mono font-semibold uppercase tracking-[0.22em] text-[var(--color-text-secondary)]"
          >
            Commit SHA
          </label>
          <div className="flex flex-col gap-2 sm:flex-row sm:items-start">
            <input
              id="pre-release-scan-sha"
              type="text"
              autoComplete="off"
              spellCheck={false}
              value={sha}
              onChange={(e) => setSha(e.target.value)}
              placeholder="e.g. a1b2c3d"
              className="w-full rounded-md border border-[var(--color-border)] bg-[var(--color-surface-raised)] px-3 py-2 text-sm font-mono"
            />
            <Button
              type="submit"
              variant="primary"
              size="sm"
              disabled={submitDisabled}
              className="shrink-0"
            >
              {submitting ? "Submitting…" : "Run scan →"}
            </Button>
          </div>
          {shaError && (
            <p className="mt-1.5 text-xs text-[var(--color-severity-critical)]">{shaError}</p>
          )}
          {scanInFlight && !shaError && (
            <p className="mt-1.5 text-xs text-[var(--color-text-secondary)]">
              A scan is already running
            </p>
          )}
        </div>

        <fieldset>
          <legend className="mb-2 text-xs font-mono font-semibold uppercase tracking-[0.22em] text-[var(--color-text-secondary)]">
            Scanners
          </legend>
          <div className="flex flex-col gap-2">
            <label className="flex items-center gap-2 text-sm text-[var(--color-text-primary)]">
              <input
                type="radio"
                name="scanner-mode"
                checked={useAllScanners}
                onChange={() => setUseAllScanners(true)}
              />
              All scanners (default)
            </label>
            <label className="flex items-center gap-2 text-sm text-[var(--color-text-primary)]">
              <input
                type="radio"
                name="scanner-mode"
                checked={!useAllScanners}
                onChange={() => setUseAllScanners(false)}
              />
              Custom
            </label>
            {!useAllScanners && (
              <div className="ml-6 flex flex-wrap gap-x-5 gap-y-2 pt-1">
                {ALL_SCANNERS.map((key) => (
                  <label
                    key={key}
                    className="flex items-center gap-2 text-sm text-[var(--color-text-primary)]"
                  >
                    <input
                      type="checkbox"
                      checked={selectedScanners.has(key)}
                      onChange={() => toggleScanner(key)}
                    />
                    {key === "dependencies" && "Dependencies (SCA)"}
                    {key === "code_scanning" && "Code Scanning (SAST)"}
                    {key === "container_scanning" && "Container (CONT)"}
                    {key === "secrets" && "Secrets (SEC)"}
                  </label>
                ))}
              </div>
            )}
          </div>
        </fieldset>

        {submitError && (
          <p className="mt-4 text-xs text-[var(--color-severity-critical)]">{submitError}</p>
        )}
      </form>

      {/* Active scan status card */}
      {activeScan && (
        <div className="rounded-md border border-[var(--color-border)] bg-[var(--color-surface)] p-5">
          <div className="flex items-center justify-between gap-3">
            <div className="flex items-center gap-2">
              <span className="text-sm font-semibold text-[var(--color-text-primary)]">
                Scan #{activeScan.scan_id.slice(0, 8)}
              </span>
            </div>
            <div className={`flex items-center gap-2 text-sm font-medium ${STATUS_STYLES[activeScan.status]}`}>
              {(activeScan.status === "queued" || activeScan.status === "running") && (
                <span className="inline-block h-2 w-2 animate-pulse rounded-full bg-[var(--color-state-pending)]" />
              )}
              {activeScan.status === "completed" && <span>✓</span>}
              {activeScan.status === "failed" && <span>×</span>}
              <span className="capitalize">{activeScan.status.replace(/_/g, " ")}</span>
            </div>
          </div>

          <div className="mt-2 flex flex-wrap items-center gap-2 text-xs text-[var(--color-text-secondary)]">
            <span className="font-mono">{shortenSha(activeScan.commit_sha)}</span>
            <span>·</span>
            <div className="flex flex-wrap gap-1">
              {activeScan.scanner_types.map((st) => (
                <span
                  key={st}
                  className="rounded px-1.5 py-0.5 text-xs font-semibold bg-[var(--color-accent-subtle)] text-[var(--color-accent)]"
                >
                  {scannerAbbrev(st)}
                </span>
              ))}
            </div>
          </div>

          {activeScan.status === "completed" && activeScan.finding_counts && (
            <div className="mt-3 flex items-center gap-4 text-sm tabular-nums">
              {(["critical", "high", "medium", "low"] as const).map((sev) => (
                <span key={sev} className={SEV_CLASSES[sev]}>
                  {activeScan.finding_counts![sev]} {sev}
                </span>
              ))}
            </div>
          )}

          {activeScan.status === "failed" && activeScan.error && (
            <p className="mt-3 text-sm text-[var(--color-severity-critical)]">
              {activeScan.error}
            </p>
          )}
        </div>
      )}
    </div>
  )
}
