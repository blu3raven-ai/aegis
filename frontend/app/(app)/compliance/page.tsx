"use client"

import { useState, useEffect, useCallback, useRef } from "react"
import { ControlsSummaryTable } from "@/components/shared/compliance/ControlsSummaryTable"
import { FrameworkCard } from "@/components/shared/compliance/FrameworkCard"
import { KpiCard } from "@/components/shared/KpiCard"
import { PageHeader } from "@/components/layout/PageHeader"
import { ComplianceIcon } from "@/lib/shared/ui/page-icons"
import {
  listFrameworks,
  getFrameworkSummary,
  deriveControlStatus,
  type ComplianceFramework,
  type ControlSummaryItem,
} from "@/lib/client/compliance-api"

const ORG_ID = process.env.NEXT_PUBLIC_ORG_ID ?? "example-org"

type StatusFilter = "all" | "unmet" | "partial" | "met"

// ─── Stats helpers ────────────────────────────────────────────────────────────

function frameworksCaption(frameworks: ComplianceFramework[]): string {
  const labels = frameworks.map((f) => f.label)
  if (labels.length <= 3) return labels.join(", ")
  return `${labels.slice(0, 3).join(", ")} +${labels.length - 3} more`
}

interface AggregatedStats {
  totalControls: number
  metControls: number
  unmetControls: number
  partialControls: number
  criticalGaps: number
  highGaps: number
}

function aggregateStats(
  frameworks: ComplianceFramework[],
  summaries: Record<string, ControlSummaryItem[]>,
  errors: Record<string, boolean>,
): AggregatedStats | null {
  // Stats are "ready" once every framework has resolved (loaded or errored).
  // Errored frameworks are excluded from the totals — partial data is better than no data.
  if (frameworks.some((fw) => !(fw.id in summaries) && !errors[fw.id])) return null

  let totalControls = 0
  let metControls = 0
  let unmetControls = 0
  let partialControls = 0
  let criticalGaps = 0
  let highGaps = 0

  for (const fw of frameworks) {
    const items = summaries[fw.id]
    if (!items) continue // errored, skip
    for (const c of items) {
      totalControls++
      const status = deriveControlStatus(c)
      if (status === "met") metControls++
      else if (status === "unmet") unmetControls++
      else if (status === "partial") partialControls++

      if (status !== "met") {
        if (c.highest_severity === "critical") criticalGaps++
        else if (c.highest_severity === "high") highGaps++
      }
    }
  }

  return { totalControls, metControls, unmetControls, partialControls, criticalGaps, highGaps }
}

// ─── Sub-components ───────────────────────────────────────────────────────────

const NEUTRAL = "text-[var(--color-text-primary)]"
const CRITICAL = "text-[var(--color-severity-critical)]"
const OK = "text-[var(--color-state-fixed)]"

function StatsStrip({
  frameworks,
  summaries,
  errors,
  anyLoading,
}: {
  frameworks: ComplianceFramework[]
  summaries: Record<string, ControlSummaryItem[]>
  errors: Record<string, boolean>
  anyLoading: boolean
}) {
  const agg = anyLoading ? null : aggregateStats(frameworks, summaries, errors)
  const passPct =
    agg !== null && agg.totalControls > 0
      ? `${Math.round((agg.metControls / agg.totalControls) * 100)}%`
      : "—"
  const passCaption =
    agg !== null
      ? `${agg.metControls} of ${agg.totalControls}`
      : "Loading…"
  const openGaps =
    agg !== null ? String(agg.unmetControls + agg.partialControls) : "—"
  const gapsCaption =
    agg !== null && (agg.criticalGaps > 0 || agg.highGaps > 0)
      ? `${agg.criticalGaps} critical · ${agg.highGaps} high`
      : agg !== null
        ? "—"
        : "Loading…"
  const openGapsValueClass = agg !== null && (agg.unmetControls + agg.partialControls) > 0 ? CRITICAL : NEUTRAL
  const passValueClass = agg !== null && agg.totalControls > 0 && agg.metControls === agg.totalControls ? OK : NEUTRAL

  return (
    <div className="grid grid-cols-2 gap-3 border-b border-[var(--color-border-divider)] bg-[var(--color-surface)] px-5 py-4 sm:grid-cols-2 lg:grid-cols-4">
      <KpiCard
        label="Frameworks tracked"
        value={String(frameworks.length)}
        note={frameworks.length > 0 ? frameworksCaption(frameworks) : "—"}
        valueClass={NEUTRAL}
      />
      <KpiCard
        label="Controls passing"
        value={passPct}
        note={passCaption}
        valueClass={passValueClass}
      />
      <KpiCard
        label="Open gaps"
        value={openGaps}
        note={gapsCaption}
        valueClass={openGapsValueClass}
      />
      <KpiCard
        label="Next attestation"
        value="—"
        note="Tracking ships in a follow-up"
        valueClass={NEUTRAL}
      />
    </div>
  )
}

// ─── Page ─────────────────────────────────────────────────────────────────────

export default function CompliancePage() {
  const [frameworks, setFrameworks] = useState<ComplianceFramework[]>([])
  const [summaries, setSummaries] = useState<Record<string, ControlSummaryItem[]>>({})
  const [errors, setErrors] = useState<Record<string, boolean>>({})
  const [selected, setSelected] = useState<string | null>(null)
  const [statusFilter, setStatusFilter] = useState<StatusFilter>("all")
  const [loadState, setLoadState] = useState<"loading" | "ok" | "error">("loading")

  const fetchSummary = useCallback((id: string) => {
    setErrors((prev) => ({ ...prev, [id]: false }))
    setSummaries((prev) => {
      const next = { ...prev }
      delete next[id]
      return next
    })
    getFrameworkSummary(id, ORG_ID)
      .then((items) => setSummaries((prev) => ({ ...prev, [id]: items })))
      .catch(() => setErrors((prev) => ({ ...prev, [id]: true })))
  }, [])

  const fetchAll = useCallback(() => {
    setLoadState("loading")
    setSummaries({})
    setErrors({})
    listFrameworks()
      .then((fws) => {
        setFrameworks(fws)
        setSelected((prev) => (prev && fws.some((f) => f.id === prev) ? prev : fws[0]?.id ?? null))
        setLoadState("ok")
        fws.forEach((fw) => fetchSummary(fw.id))
      })
      .catch(() => setLoadState("error"))
  }, [fetchSummary])

  useEffect(() => {
    fetchAll()
  }, [fetchAll])

  // Reset filter when the user switches frameworks to avoid empty filter
  // results. Skip the first run since `selected` flips from null → initial
  // framework after the list loads.
  const didMountRef = useRef(false)
  useEffect(() => {
    if (!didMountRef.current) {
      didMountRef.current = true
      return
    }
    setStatusFilter("all")
  }, [selected])

  // ── Derived values for ControlsSection ──────────────────────────────────────
  const selectedFw = frameworks.find((f) => f.id === selected)
  const selectedSummary = selected !== null ? (summaries[selected] ?? []) : []
  const counts = {
    all: selectedSummary.length,
    unmet: selectedSummary.filter((c) => deriveControlStatus(c) === "unmet").length,
    partial: selectedSummary.filter((c) => deriveControlStatus(c) === "partial").length,
    met: selectedSummary.filter((c) => deriveControlStatus(c) === "met").length,
  }
  const visibleCount =
    statusFilter === "all" ? counts.all : counts[statusFilter]
  const anyLoading =
    loadState === "ok" && frameworks.some((fw) => !(fw.id in summaries) && !errors[fw.id])

  const filterLabels: { key: StatusFilter; label: string }[] = [
    { key: "all", label: `All (${counts.all})` },
    { key: "unmet", label: `Unmet (${counts.unmet})` },
    { key: "partial", label: `Partial (${counts.partial})` },
    { key: "met", label: `Met (${counts.met})` },
  ]

  // ── Render ───────────────────────────────────────────────────────────────────

  return (
    <div className="flex h-full flex-col bg-[var(--color-bg)]">
      <PageHeader
        icon={<ComplianceIcon />}
        title="Compliance"
        description="Map findings to controls · audit-ready exports"
        controls={
          <>
            <button
              type="button"
              disabled
              title="Coming soon"
              className="rounded-lg border border-[var(--color-border)] bg-[var(--color-surface)] px-3 py-1.5 text-xs font-medium text-[var(--color-text-secondary)] disabled:cursor-not-allowed disabled:opacity-50"
            >
              Export attestation
            </button>
            <button
              type="button"
              disabled
              title="Coming soon"
              className="rounded-lg border border-[var(--color-border)] bg-[var(--color-surface)] px-3 py-1.5 text-xs font-medium text-[var(--color-text-secondary)] disabled:cursor-not-allowed disabled:opacity-50"
            >
              Add framework
            </button>
          </>
        }
      />

      {loadState === "ok" && frameworks.length > 0 && (
        <StatsStrip
          frameworks={frameworks}
          summaries={summaries}
          errors={errors}
          anyLoading={anyLoading}
        />
      )}

      <div className="flex flex-col gap-6 p-6">

        {loadState === "loading" && (
          <>
            <div className="grid grid-cols-2 gap-3 sm:grid-cols-2 lg:grid-cols-4">
              {Array.from({ length: 4 }).map((_, i) => (
                <div
                  key={i}
                  className="rounded-xl border border-[var(--color-border)] bg-[var(--color-surface-raised)] px-5 py-3"
                >
                  <div className="text-[11px] font-semibold uppercase tracking-[0.22em] text-[var(--color-text-secondary)]">
                    —
                  </div>
                  <div className="mt-2 text-2xl font-semibold leading-none tabular-nums text-[var(--color-text-primary)]">
                    —
                  </div>
                  <div className="mt-2 text-sm text-[var(--color-text-secondary)]">—</div>
                </div>
              ))}
            </div>
            <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
              {Array.from({ length: 3 }).map((_, i) => (
                <div
                  key={i}
                  className="animate-pulse rounded-xl border border-[var(--color-border)] bg-[var(--color-surface)] p-5"
                >
                  <div className="mb-3 h-4 w-1/2 rounded bg-[var(--color-border)]" />
                  <div className="mb-3 h-1.5 w-full rounded-full bg-[var(--color-border)]" />
                  <div className="h-3 w-2/3 rounded bg-[var(--color-border)]" />
                </div>
              ))}
            </div>
            <div className="rounded-xl border border-[var(--color-border)] bg-[var(--color-surface)] p-5 shadow-[var(--shadow-card)]">
              <div className="flex items-center justify-center py-12 text-sm text-[var(--color-text-secondary)]">
                Loading frameworks…
              </div>
            </div>
          </>
        )}

        {loadState === "error" && (
          <div className="flex flex-col items-center justify-center gap-3 rounded-xl border border-[var(--color-border)] bg-[var(--color-surface)] px-8 py-16 text-center">
            <p className="text-base font-semibold text-[var(--color-text-primary)]">
              Couldn&apos;t load compliance frameworks
            </p>
            <p className="text-sm text-[var(--color-text-secondary)]">
              Check the backend connection and try again.
            </p>
            <button
              type="button"
              onClick={fetchAll}
              className="mt-1 rounded-lg border border-[var(--color-border)] px-3 py-1.5 text-xs font-semibold text-[var(--color-text-secondary)] transition-colors hover:border-[var(--color-border-strong)] hover:text-[var(--color-text-primary)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)]"
            >
              Retry
            </button>
          </div>
        )}

        {loadState === "ok" && frameworks.length === 0 && (
          <div className="flex flex-col items-center justify-center gap-4 rounded-xl border border-[var(--color-border)] bg-[var(--color-surface)] py-20 text-center">
            <div className="flex h-16 w-16 items-center justify-center rounded-2xl bg-[var(--color-surface-raised)] text-[var(--color-text-tertiary)]">
              <svg
                className="h-8 w-8"
                viewBox="0 0 24 24"
                fill="none"
                stroke="currentColor"
                strokeWidth={1.2}
                strokeLinecap="round"
                strokeLinejoin="round"
                aria-hidden="true"
              >
                <path d="M9 12.75 11.25 15 15 9.75M21 12c0 1.268-.63 2.39-1.593 3.068a3.745 3.745 0 0 1-1.043 3.296 3.745 3.745 0 0 1-3.296 1.043A3.745 3.745 0 0 1 12 21c-1.268 0-2.39-.63-3.068-1.593a3.746 3.746 0 0 1-3.296-1.043 3.745 3.745 0 0 1-1.043-3.296A3.745 3.745 0 0 1 3 12c0-1.268.63-2.39 1.593-3.068a3.745 3.745 0 0 1 1.043-3.296 3.746 3.746 0 0 1 3.296-1.043A3.746 3.746 0 0 1 12 3c1.268 0 2.39.63 3.068 1.593a3.746 3.746 0 0 1 3.296 1.043 3.746 3.746 0 0 1 1.043 3.296A3.745 3.745 0 0 1 21 12Z" />
              </svg>
            </div>
            <div className="flex flex-col gap-1">
              <p className="text-base font-semibold text-[var(--color-text-primary)]">
                No frameworks tracked yet
              </p>
              <p className="max-w-sm text-sm text-[var(--color-text-secondary)]">
                Add a framework to start mapping findings to compliance controls.
              </p>
            </div>
            <button
              type="button"
              disabled
              title="Coming soon"
              className="rounded-lg border border-[var(--color-border)] bg-[var(--color-surface)] px-4 py-2 text-sm font-medium text-[var(--color-text-secondary)] disabled:cursor-not-allowed disabled:opacity-50"
            >
              Add framework
            </button>
          </div>
        )}

        {loadState === "ok" && frameworks.length > 0 && (
          <>
            <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
              {frameworks.map((fw) => (
                <FrameworkCard
                  key={fw.id}
                  framework={fw}
                  summary={summaries[fw.id] ?? null}
                  error={errors[fw.id] === true}
                  selected={selected === fw.id}
                  onClick={() => setSelected(fw.id)}
                  onRetry={() => fetchSummary(fw.id)}
                />
              ))}
            </div>

            {selected !== null && (
              <div className="rounded-xl border border-[var(--color-border)] bg-[var(--color-surface)] p-5 shadow-[var(--shadow-card)]">
                <div className="mb-4 flex items-center justify-between gap-4">
                  <h2 className="text-base font-semibold text-[var(--color-text-primary)]">
                    Controls · {selectedFw?.label ?? selected}
                  </h2>
                  {!errors[selected] && (
                    <span className="shrink-0 text-xs text-[var(--color-text-secondary)]">
                      Showing {visibleCount} of {counts.all}
                    </span>
                  )}
                </div>

                {errors[selected] ? (
                  <div className="flex flex-col items-center justify-center gap-2 py-12 text-center">
                    <p className="text-sm text-[var(--color-text-secondary)]">
                      Couldn&apos;t load controls for this framework.
                    </p>
                    <button
                      type="button"
                      onClick={() => fetchSummary(selected)}
                      className="rounded-lg border border-[var(--color-border)] px-3 py-1.5 text-xs font-semibold text-[var(--color-text-secondary)] transition-colors hover:border-[var(--color-border-strong)] hover:text-[var(--color-text-primary)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)]"
                    >
                      Retry
                    </button>
                  </div>
                ) : (
                  <>
                    <div className="mb-4 flex flex-wrap gap-1.5">
                      {filterLabels.map(({ key, label }) => (
                        <button
                          key={key}
                          type="button"
                          aria-pressed={statusFilter === key}
                          onClick={() => setStatusFilter(key)}
                          className={[
                            "rounded-md px-3 py-1.5 text-xs font-medium transition-colors",
                            statusFilter === key
                              ? "bg-[var(--color-accent)] text-[var(--color-accent-on)]"
                              : "bg-[var(--color-surface-raised)] text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)]",
                          ].join(" ")}
                        >
                          {label}
                        </button>
                      ))}
                    </div>

                    {/* Distinguish "not yet fetched" from "fetched and empty" so the table doesn't flash an empty state */}
                    {!(selected in summaries) ? (
                      <div className="flex items-center justify-center py-12 text-sm text-[var(--color-text-secondary)]">
                        Loading controls…
                      </div>
                    ) : (
                      <ControlsSummaryTable
                        controls={selectedSummary}
                        framework={selected}
                        statusFilter={statusFilter}
                      />
                    )}
                  </>
                )}
              </div>
            )}
          </>
        )}

      </div>
    </div>
  )
}
