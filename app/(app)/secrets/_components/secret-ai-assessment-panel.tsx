"use client"

import { useState } from "react"
import type React from "react"
import type { ClassificationEntry, SecretFinding } from "@/lib/shared/secrets/types"
import { resolveClassification } from "@/lib/shared/secrets/dashboard-utils"

export const VALUE_STYLES: Record<string, string> = {
  // Current values
  verified_secret:
    "border border-[var(--color-accent)] bg-[var(--color-accent)]/10 text-[var(--color-accent)]",
  likely_secret:
    "border border-[var(--color-accent)]/50 bg-transparent text-[var(--color-accent)]",
  not_secret:
    "border border-[var(--color-border-strong)] bg-transparent text-[var(--color-text-tertiary)]",
  uncertain:
    "border border-[var(--color-border-strong)] bg-transparent text-[var(--color-text-tertiary)]",
  // Legacy values (findings stored before schema change)
  is_secret:
    "border border-[var(--color-accent)]/50 bg-transparent text-[var(--color-accent)]",
  is_not_secret:
    "border border-[var(--color-border-strong)] bg-transparent text-[var(--color-text-tertiary)]",
  confirmed:
    "border border-[var(--color-accent)]/50 bg-transparent text-[var(--color-accent)]",
  likely_real:
    "border border-[var(--color-accent)]/50 bg-transparent text-[var(--color-accent)]",
  false_positive:
    "border border-[var(--color-border-strong)] bg-transparent text-[var(--color-text-tertiary)]",
}

export const VALUE_LABELS: Record<string, string> = {
  // Current values
  verified_secret: "Verified Secret",
  likely_secret: "Likely Secret",
  not_secret: "Not a Secret",
  uncertain: "Uncertain",
  // Legacy values
  is_secret: "Is Secret",
  is_not_secret: "Not a Secret",
  confirmed: "Confirmed",
  likely_real: "Likely real",
  false_positive: "False positive",
}

// Icon SVGs per value — inline, no external dependency
export const VALUE_ICONS: Record<string, React.ReactNode> = {
  verified_secret: (
    <svg className="inline-block mr-1 -mt-px" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
      <polyline points="9 12 11 14 15 10" />
    </svg>
  ),
  likely_secret: (
    <svg className="inline-block mr-1 -mt-px" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d="M12 3l1.9 5.8H20l-4.9 3.6 1.9 5.8L12 15l-5 3.2 1.9-5.8L4 8.8h6.1z" />
    </svg>
  ),
}


export function formatRelativeTime(iso: string): string {
  const diff = Date.now() - new Date(iso).getTime()
  const mins = Math.floor(diff / 60_000)
  if (mins < 60) return `${Math.max(1, mins)}m ago`
  const hours = Math.floor(diff / 3_600_000)
  if (hours < 24) return `${hours}h ago`
  const days = Math.floor(diff / 86_400_000)
  return `${days}d ago`
}

export function formatScanDepth(scanDepth: ClassificationEntry["scanDepth"]): string {
  if (!scanDepth) return "Unknown"
  const labels: Record<string, string> = {
    light: "Light Scan",
    deep: "Deep Scan",
    ai_enhanced: "AI Enhanced",
  }
  return labels[scanDepth] ?? scanDepth
}

export function ScannerClassificationPanel({ finding }: { finding: SecretFinding | null }) {
  const [expanded, setExpanded] = useState(false)
  const history = finding?.classificationHistory ?? []
  const active = resolveClassification(history)
  const historyNewestFirst = [...history].reverse()
  const showToggle = history.length > 1

  return (
    <section className="rounded-2xl border border-[var(--color-border)] bg-[var(--color-surface-raised)] p-4">
      <div className="flex items-start justify-between gap-2">
        <p className="text-xs font-semibold uppercase tracking-[0.18em] text-[var(--color-text-secondary)]">
          Scanner Classification
        </p>
        {active && (
          <span className="shrink-0 tabular-nums text-xs text-[var(--color-text-secondary)]">
            {formatRelativeTime(active.scannedAt)}
          </span>
        )}
      </div>
      <p className="mt-1 text-xs text-[var(--color-text-secondary)]">
        Classification produced by the scanner at scan time.
      </p>

      {!active ? (
        <p className="mt-3 text-xs text-[var(--color-text-secondary)]">
          No scanner classification available for this finding.
        </p>
      ) : (
        <>
          <div className="mt-4 flex flex-wrap items-center gap-2">
            <span
              className={`rounded-full border px-2.5 py-1 text-xs font-medium ${VALUE_STYLES[active.value] ?? VALUE_STYLES["uncertain"]}`}
            >
              {VALUE_ICONS[active.value]}
              {VALUE_LABELS[active.value] ?? active.value}
            </span>
            {active.confidence != null && (
              <span className="rounded-full border border-[var(--color-border)] bg-[var(--color-surface)] px-2.5 py-1 text-xs tabular-nums text-[var(--color-text-secondary)]">
                {(active.confidence * 100).toFixed(0)}% confidence
              </span>
            )}
          </div>
          <p className="mt-4 text-xs italic text-[var(--color-text-secondary)]">
            Classification is a scanner signal, not a guarantee.
          </p>

          {showToggle && (
            <button
              type="button"
              onClick={() => setExpanded((v) => !v)}
              className="mt-3 text-xs text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)]"
            >
              {expanded ? "▼ Hide scan history" : `▶ Show scan history (${history.length} runs)`}
            </button>
          )}

          {expanded && (
            <div className="mt-3">
              {historyNewestFirst.map((entry, i) => {
                const isLast = i === historyNewestFirst.length - 1
                const isGoverning =
                  active != null &&
                  entry.value === active.value &&
                  entry.scannedAt === active.scannedAt
                return (
                  <div
                    key={`${entry.runId}-${entry.source}-${i}`}
                    className={`relative flex gap-2.5 ${!isLast ? "pb-2.5" : ""}`}
                  >
                    {!isLast && (
                      <div
                        className="absolute bottom-0 top-[13px] w-px bg-[var(--color-border)]"
                        style={{ left: "3.5px" }}
                        aria-hidden="true"
                      />
                    )}
                    <div className="relative z-10 shrink-0 pt-[5px]">
                      <div
                        className={`h-2 w-2 rounded-full ${isGoverning ? "bg-[var(--color-accent)]" : "bg-[var(--color-text-tertiary)]"}`}
                        aria-hidden="true"
                      />
                    </div>
                    <div
                      className={`flex-1 rounded-lg border px-2.5 py-2 text-xs ${isGoverning ? "border-[var(--color-accent)]/25 bg-[var(--color-accent)]/8" : "border-[var(--color-border)] bg-[var(--color-surface)]"}`}
                    >
                      <div className="flex items-center justify-between gap-2">
                        <span
                          className={`font-medium ${isGoverning ? "text-[var(--color-text-primary)]" : "text-[var(--color-text-secondary)]"}`}
                        >
                          {formatScanDepth(entry.scanDepth)}
                        </span>
                        <span className="tabular-nums text-[11px] text-[var(--color-text-tertiary)]">
                          {formatRelativeTime(entry.scannedAt)}
                        </span>
                      </div>
                      <div className="mt-1.5 flex items-center gap-2">
                        <span
                          className={`rounded-full border px-1.5 py-0.5 text-2xs font-medium ${VALUE_STYLES[entry.value] ?? VALUE_STYLES["uncertain"]}`}
                        >
                          {VALUE_ICONS[entry.value]}
                          {VALUE_LABELS[entry.value] ?? entry.value}
                        </span>
                        {entry.confidence != null && (
                          <span className="tabular-nums text-[11px] text-[var(--color-text-tertiary)]">
                            {(entry.confidence * 100).toFixed(0)}%
                          </span>
                        )}
                        {isGoverning && (
                          <span
                            className="ml-auto text-2xs font-medium text-[var(--color-accent)]"
                            title="Highest-confidence result — takes priority over more recent scans"
                          >
                            Effective
                          </span>
                        )}
                      </div>
                    </div>
                  </div>
                )
              })}
            </div>
          )}
        </>
      )}
    </section>
  )
}
