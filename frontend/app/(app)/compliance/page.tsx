"use client"

import { useState, useEffect, useCallback, useRef } from "react"
import { AttestationExportButton } from "@/components/shared/compliance/AttestationExportButton"
import { ControlsSummaryTable } from "@/components/shared/compliance/ControlsSummaryTable"
import { FrameworkCard } from "@/components/shared/compliance/FrameworkCard"
import { PostureTrendKpiCard } from "@/components/shared/compliance/PostureTrendKpiCard"
import { KpiCard } from "@/components/shared/KpiCard"
import { PageHeader } from "@/components/layout/PageHeader"
import { ComplianceIcon } from "@/lib/shared/ui/page-icons"
import { Button } from "@/components/ui/Button"
import { Card } from "@/components/ui/Card"
import { FilterChip } from "@/components/ui/FilterChip"
import { SearchInput } from "@/components/shared/SearchInput"
import {
  listFrameworks,
  getFrameworkSummary,
  deriveControlStatus,
  type ComplianceFramework,
  type ControlSummaryItem,
} from "@/lib/client/compliance-api"
import { AddFrameworkModal } from "./AddFrameworkModal"

type StatusFilter = "all" | "unmet" | "partial" | "met"


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
  overdueControls: number
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
  let overdueControls = 0

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

      if (c.overdue === true) overdueControls++
    }
  }

  return { totalControls, metControls, unmetControls, partialControls, criticalGaps, highGaps, overdueControls }
}


const NEUTRAL = "text-[var(--color-text-primary)]"
const CRITICAL = "text-[var(--color-severity-critical-text)]"
const OK = "text-[var(--color-state-fixed-text)]"

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
  // Errored frameworks are excluded from the aggregate totals; surface that so
  // the passing % / open-gap counts aren't read as the whole picture.
  const erroredCount = frameworks.filter((fw) => errors[fw.id]).length
  const unavailableSuffix =
    agg !== null && erroredCount > 0
      ? ` · ${erroredCount} framework${erroredCount > 1 ? "s" : ""} unavailable`
      : ""
  const passPct =
    agg !== null && agg.totalControls > 0
      ? `${Math.round((agg.metControls / agg.totalControls) * 100)}%`
      : "—"
  const passCaption =
    agg !== null
      ? `${agg.metControls} of ${agg.totalControls}${unavailableSuffix}`
      : "Loading…"
  const openGaps =
    agg !== null ? String(agg.unmetControls + agg.partialControls) : "—"
  // Past-due controls are a distinct urgency signal from raw gap severity, so
  // surface them alongside the critical/high breakdown rather than as a new card.
  const overdueSuffix =
    agg !== null && agg.overdueControls > 0 ? ` · ${agg.overdueControls} overdue` : ""
  const gapsCaption =
    agg !== null && (agg.criticalGaps > 0 || agg.highGaps > 0)
      ? `${agg.criticalGaps} critical · ${agg.highGaps} high${overdueSuffix}${unavailableSuffix}`
      : agg !== null
        ? `—${overdueSuffix}${unavailableSuffix}`
        : "Loading…"
  const openGapsValueClass = agg !== null && (agg.unmetControls + agg.partialControls) > 0 ? CRITICAL : NEUTRAL
  const passValueClass = agg !== null && agg.totalControls > 0 && agg.metControls === agg.totalControls ? OK : NEUTRAL

  // Strip sits inside the page body — no bg/border on the strip itself so it
  // doesn't visually glue to the PageHeader band above. KpiCard primitives
  // carry their own surface treatment.
  return (
    <div className="grid grid-cols-2 gap-3 sm:grid-cols-2 lg:grid-cols-4">
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
      <PostureTrendKpiCard days={30} />
    </div>
  )
}


export default function CompliancePage() {
  const [frameworks, setFrameworks] = useState<ComplianceFramework[]>([])
  const [summaries, setSummaries] = useState<Record<string, ControlSummaryItem[]>>({})
  const [errors, setErrors] = useState<Record<string, boolean>>({})
  const [selected, setSelected] = useState<string | null>(null)
  const [statusFilter, setStatusFilter] = useState<StatusFilter>("all")
  const [controlQuery, setControlQuery] = useState("")
  const [loadState, setLoadState] = useState<"loading" | "ok" | "error">("loading")
  const [addModalOpen, setAddModalOpen] = useState(false)

  const fetchSummary = useCallback((id: string) => {
    setErrors((prev) => ({ ...prev, [id]: false }))
    setSummaries((prev) => {
      const next = { ...prev }
      delete next[id]
      return next
    })
    getFrameworkSummary(id)
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
    setControlQuery("")
  }, [selected])

  // ── Derived values for ControlsSection ──────────────────────────────────────
  const selectedFw = frameworks.find((f) => f.id === selected)
  const fullSummary = selected !== null ? (summaries[selected] ?? []) : []
  // Free-text find across the (now 20-36 control) catalog by id or title.
  const query = controlQuery.trim().toLowerCase()
  const selectedSummary = query
    ? fullSummary.filter(
        (c) =>
          c.control_id.toLowerCase().includes(query) ||
          c.title.toLowerCase().includes(query),
      )
    : fullSummary
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

  // Labels mirror the status pills + hero badge (Compliant / Partial / At Risk)
  // so a filter and the rows it filters speak one vocabulary; keys stay the
  // internal met/partial/unmet.
  const filterLabels: { key: StatusFilter; label: string }[] = [
    { key: "all", label: `All (${counts.all})` },
    { key: "unmet", label: `At Risk (${counts.unmet})` },
    { key: "partial", label: `Partial (${counts.partial})` },
    { key: "met", label: `Compliant (${counts.met})` },
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
            <AttestationExportButton frameworkId={selected} />
            <Button variant="secondary" size="md" onClick={() => setAddModalOpen(true)}>
              Add framework
            </Button>
          </>
        }
      />

      <div className="flex flex-col gap-6 p-6">
        {loadState === "ok" && frameworks.length > 0 && (
          <StatsStrip
            frameworks={frameworks}
            summaries={summaries}
            errors={errors}
            anyLoading={anyLoading}
          />
        )}

        {loadState === "loading" && (
          <>
            <div className="grid grid-cols-2 gap-3 sm:grid-cols-2 lg:grid-cols-4">
              {Array.from({ length: 4 }).map((_, i) => (
                <div
                  key={i}
                  className="rounded-md border border-[var(--color-border)] bg-[var(--color-surface-raised)] px-5 py-3"
                >
                  <div className="font-mono text-[11px] font-semibold uppercase tracking-[0.22em] text-[var(--color-text-secondary)]">
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
                <Card
                  key={i}
                  className="animate-pulse rounded-md"
                >
                  <div className="mb-3 h-4 w-1/2 rounded bg-[var(--color-border)]" />
                  <div className="mb-3 h-1.5 w-full rounded-full bg-[var(--color-border)]" />
                  <div className="h-3 w-2/3 rounded bg-[var(--color-border)]" />
                </Card>
              ))}
            </div>
            <Card elevation="sm" className="rounded-md">
              <div className="flex items-center justify-center py-12 text-sm text-[var(--color-text-secondary)]">
                Loading frameworks…
              </div>
            </Card>
          </>
        )}

        {loadState === "error" && (
          <Card padding="none" className="flex flex-col items-center justify-center gap-3 rounded-md px-8 py-16 text-center">
            <p className="text-base font-semibold text-[var(--color-text-primary)]">
              Couldn&apos;t load compliance frameworks
            </p>
            <p className="text-sm text-[var(--color-text-secondary)]">
              Check the backend connection and try again.
            </p>
            <div className="mt-1">
              <Button variant="secondary" size="sm" onClick={fetchAll}>
                Retry
              </Button>
            </div>
          </Card>
        )}

        {loadState === "ok" && frameworks.length === 0 && (
          <Card padding="none" className="flex flex-col items-center justify-center gap-4 rounded-md py-20 text-center">
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
            <Button variant="secondary" size="md" onClick={() => setAddModalOpen(true)}>
              Add framework
            </Button>
          </Card>
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
              <Card elevation="sm" className="rounded-md">
                <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
                  <h2 className="min-w-0 break-words text-base font-semibold text-[var(--color-text-primary)]">
                    Controls · {selectedFw?.label ?? selected}
                  </h2>
                  {!errors[selected] && (
                    <div className="flex items-center gap-3">
                      <div className="w-56">
                        <SearchInput
                          value={controlQuery}
                          onChange={setControlQuery}
                          placeholder="Search controls…"
                        />
                      </div>
                      <span className="shrink-0 text-xs text-[var(--color-text-secondary)] tabular-nums">
                        {visibleCount} of {fullSummary.length}
                      </span>
                    </div>
                  )}
                </div>

                {errors[selected] ? (
                  <div className="flex flex-col items-center justify-center gap-2 py-12 text-center">
                    <p className="text-sm text-[var(--color-text-secondary)]">
                      Couldn&apos;t load controls for this framework.
                    </p>
                    <Button variant="secondary" size="sm" onClick={() => fetchSummary(selected)}>
                      Retry
                    </Button>
                  </div>
                ) : (
                  <>
                    <div className="mb-4 flex flex-wrap gap-1.5">
                      {filterLabels.map(({ key, label }) => (
                        <FilterChip
                          key={key}
                          label={label}
                          active={statusFilter === key}
                          onClick={() => setStatusFilter(key)}
                        />
                      ))}
                    </div>

                    {/* Distinguish "not yet fetched" from "fetched and empty" so the table doesn't flash an empty state */}
                    {!(selected in summaries) ? (
                      <div className="flex items-center justify-center py-12 text-sm text-[var(--color-text-secondary)]">
                        Loading controls…
                      </div>
                    ) : controlQuery.trim() !== "" && selectedSummary.length === 0 ? (
                      // A search with no matches is distinct from a framework with
                      // zero controls — don't let the table imply the latter.
                      <div className="flex items-center justify-center py-12 text-sm text-[var(--color-text-secondary)]">
                        No controls match your search.
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
              </Card>
            )}
          </>
        )}

      </div>

      <AddFrameworkModal
        open={addModalOpen}
        onClose={() => setAddModalOpen(false)}
        onCreated={() => {
          setAddModalOpen(false)
          fetchAll()
        }}
      />
    </div>
  )
}
