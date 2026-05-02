"use client"

import type { SecretFinding } from "@/lib/shared/secrets/types"
import { resolveClassification } from "@/lib/shared/secrets/dashboard-utils"
import {
  VALUE_STYLES,
  VALUE_LABELS,
  VALUE_ICONS,
  formatRelativeTime,
  formatScanDepth,
} from "@/app/(app)/secrets/_components/secret-ai-assessment-panel"

const VALUE_DESCRIPTIONS: Record<string, string> = {
  verified_secret: "Confirmed as a real credential by the scanner.",
  likely_secret: "High-confidence signal — likely a real secret but not fully verified.",
  uncertain: "Scanner could not determine whether this is a real secret.",
  not_secret: "Scanner determined this is likely a false positive.",
  // Legacy
  is_secret: "Confirmed as a real credential by the scanner.",
  is_not_secret: "Scanner determined this is likely a false positive.",
  confirmed: "Confirmed as a real credential by the scanner.",
  likely_real: "High-confidence signal — likely a real secret but not fully verified.",
  false_positive: "Scanner determined this is likely a false positive.",
}

export function DetectionHistoryPanel({ finding }: { finding: SecretFinding | null }) {
  const history = finding?.classificationHistory ?? []

  if (history.length === 0) return null

  const active = resolveClassification(history)
  if (!active) return null

  // Header shows when the most recent scan ran (not when the governing entry ran).
  // history is stored oldest→newest; last element is the latest scan.
  const latestEntry = history[history.length - 1]

  const showTimeline = history.length >= 1

  return (
    <section className="rounded-2xl border border-[var(--color-border)] bg-[var(--color-surface-raised)] p-4">
      {/* Header */}
      <p className="text-xs font-semibold uppercase tracking-[0.18em] text-[var(--color-text-secondary)]">
        Detection History
      </p>
      <p className="mt-1 text-xs text-[var(--color-text-tertiary)]">
        The verdict reflects the highest-confidence scan result, not the most recent.
      </p>

      {/* Classification sub-box */}
      <div className="mt-3 rounded-xl border border-[var(--color-border)] p-3">
        <p className="text-[10px] font-semibold uppercase tracking-[0.18em] text-[var(--color-text-tertiary)]">
          Classification
        </p>
        <div className="mt-2.5 flex items-start gap-2.5 text-xs">
          <span className="mt-0.5 w-14 shrink-0 text-[var(--color-text-tertiary)]">Verdict</span>
          <div className="min-w-0">
            <div className="flex items-center gap-2">
              <span className={`rounded-full border px-2 py-0.5 font-medium ${VALUE_STYLES[active.value] ?? VALUE_STYLES["uncertain"]}`}>
                {VALUE_ICONS[active.value]}
                {VALUE_LABELS[active.value] ?? active.value}
              </span>
              {active.confidence != null && (
                <span className="tabular-nums text-[var(--color-text-tertiary)]">
                  {(active.confidence * 100).toFixed(0)}%
                </span>
              )}
            </div>
            {VALUE_DESCRIPTIONS[active.value] && (
              <p className="mt-1.5 text-[var(--color-text-secondary)]">
                {VALUE_DESCRIPTIONS[active.value]}
              </p>
            )}
          </div>
        </div>
      </div>

      {/* Scan Timeline sub-box */}
      {showTimeline && (
        <div className="mt-2 rounded-xl border border-[var(--color-border)] p-3">
          <p className="text-[10px] font-semibold uppercase tracking-[0.18em] text-[var(--color-text-tertiary)]">
            Scan Timeline
          </p>

          <div className="mt-3">
            {history.map((entry, i) => {
              const isLast = i === history.length - 1
              const isGoverning =
                entry.value === active.value && entry.scannedAt === active.scannedAt

              return (
                <div
                  key={`${entry.runId}-${entry.source}-${i}`}
                  className={`relative flex gap-2.5 ${!isLast ? "pb-2.5" : ""}`}
                >
                  {/* Absolute connector line — positioned relative to this row */}
                  {!isLast && (
                    <div
                      className="absolute bottom-0 top-[13px] w-px bg-[var(--color-border)]"
                      style={{ left: "3.5px" }}
                      aria-hidden="true"
                    />
                  )}

                  {/* Dot */}
                  <div className="relative z-10 shrink-0 pt-[5px]">
                    <div
                      className={`h-2 w-2 rounded-full ${
                        isGoverning
                          ? "bg-[var(--color-accent)]"
                          : "bg-[var(--color-text-tertiary)]"
                      }`}
                      aria-hidden="true"
                    />
                  </div>

                  {/* Entry card */}
                  <div
                    className={`flex-1 rounded-lg border px-2.5 py-2 text-xs ${
                      isGoverning
                        ? "border-[var(--color-accent)]/25 bg-[var(--color-accent)]/8"
                        : "border-[var(--color-border)] bg-[var(--color-surface)]"
                    }`}
                  >
                    {/* Row 1: scan type + timestamp */}
                    <div className="flex items-center justify-between gap-2">
                      <span
                        className={`font-medium ${
                          isGoverning
                            ? "text-[var(--color-text-primary)]"
                            : "text-[var(--color-text-secondary)]"
                        }`}
                      >
                        {formatScanDepth(entry.scanDepth)}
                      </span>
                      <span className="tabular-nums text-[11px] text-[var(--color-text-tertiary)]">
                        {formatRelativeTime(entry.scannedAt)}
                      </span>
                    </div>

                    {/* Row 2: badge + confidence + governing label */}
                    <div className="mt-1.5 flex items-center gap-2">
                      <span
                        className={`rounded-full border px-1.5 py-0.5 text-[10px] font-medium ${VALUE_STYLES[entry.value] ?? VALUE_STYLES["uncertain"]}`}
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
                          className="ml-auto text-[10px] font-medium text-[var(--color-accent)]"
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
        </div>
      )}
    </section>
  )
}
