"use client"

import { useState, useEffect, useCallback } from "react"
import { InsightsHeader, type WindowDays, type SeverityFilter } from "@/components/shared/insights/InsightsHeader"
import { FindingsOverTimeChart } from "@/components/shared/insights/FindingsOverTimeChart"
import { TopAuthorsList } from "@/components/shared/insights/TopAuthorsList"
import { MttrTable } from "@/components/shared/insights/MttrTable"
import { AnomaliesPanel } from "@/components/shared/insights/AnomaliesPanel"
import {
  fetchTemporalSeries,
  fetchTopAuthors,
  fetchMttr,
  type TemporalSeriesPoint,
  type TopAuthor,
  type MttrRow,
} from "@/lib/client/temporal-api"

const ORG_ID = process.env.NEXT_PUBLIC_ORG_ID ?? "example-org"

function SectionCard({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="rounded-xl border border-[var(--color-border)] bg-[var(--color-surface)] shadow-[var(--shadow-card)] overflow-hidden">
      <div className="border-b border-[var(--color-border)] px-5 py-3">
        <h2 className="text-[13px] font-semibold text-[var(--color-text-primary)]">{title}</h2>
      </div>
      <div className="px-5 py-4">{children}</div>
    </div>
  )
}

type LoadState = "loading" | "ok" | "error"

interface InsightsContentProps {
  /** When true, hides the InsightsHeader (caller renders its own chrome, e.g. Home tabs). */
  hideHeader?: boolean
}

export function InsightsContent({ hideHeader = false }: InsightsContentProps = {}) {
  const [windowDays, setWindowDays] = useState<WindowDays>(30)
  const [severity, setSeverity] = useState<SeverityFilter>("all")

  const [seriesPoints, setSeriesPoints] = useState<TemporalSeriesPoint[]>([])
  const [seriesState, setSeriesState] = useState<LoadState>("loading")

  const [authors, setAuthors] = useState<TopAuthor[]>([])
  const [authorsState, setAuthorsState] = useState<LoadState>("loading")

  const [mttrRows, setMttrRows] = useState<MttrRow[]>([])
  const [mttrState, setMttrState] = useState<LoadState>("loading")

  const load = useCallback(async () => {
    setSeriesState("loading")
    setAuthorsState("loading")
    setMttrState("loading")

    const sevParam = severity === "all" ? undefined : severity

    await Promise.allSettled([
      fetchTemporalSeries({
        metric: "findings_introduced",
        org_id: ORG_ID,
        bucket_size: windowDays <= 7 ? "1h" : "1d",
        since_days: windowDays,
        severity: sevParam,
      })
        .then((pts) => { setSeriesPoints(pts); setSeriesState("ok") })
        .catch(() => setSeriesState("error")),

      fetchTopAuthors({ org_id: ORG_ID, since_days: windowDays, limit: 10 })
        .then((a) => { setAuthors(a); setAuthorsState("ok") })
        .catch(() => setAuthorsState("error")),

      fetchMttr({ org_id: ORG_ID, since_days: windowDays, group_by: "scanner_type" })
        .then((rows) => { setMttrRows(rows); setMttrState("ok") })
        .catch(() => setMttrState("error")),
    ])
  }, [windowDays, severity])

  useEffect(() => { void load() }, [load])

  return (
    <>
      {!hideHeader && (
        <InsightsHeader
          windowDays={windowDays}
          severity={severity}
          onWindowChange={(w) => setWindowDays(w)}
          onSeverityChange={(s) => setSeverity(s)}
        />
      )}
      {hideHeader && (
        <div className="mb-4 flex flex-wrap items-center gap-2">
          <InsightsHeaderControls
            windowDays={windowDays}
            severity={severity}
            onWindowChange={(w) => setWindowDays(w)}
            onSeverityChange={(s) => setSeverity(s)}
          />
        </div>
      )}

      <div className={hideHeader ? "flex flex-col gap-5" : "mx-auto w-full max-w-5xl flex-1 px-5 py-6 flex flex-col gap-5"}>
        <SectionCard title="Findings introduced over time">
          <FindingsOverTimeChart
            points={seriesPoints}
            loading={seriesState === "loading"}
            error={seriesState === "error"}
          />
        </SectionCard>

        <div className="grid grid-cols-1 gap-5 md:grid-cols-2">
          <SectionCard title="Top authors (introduced)">
            <TopAuthorsList
              authors={authors}
              loading={authorsState === "loading"}
              error={authorsState === "error"}
            />
          </SectionCard>

          <SectionCard title="MTTR by scanner">
            <MttrTable
              rows={mttrRows}
              loading={mttrState === "loading"}
              error={mttrState === "error"}
            />
          </SectionCard>
        </div>

        <SectionCard title="Anomalies (last 30 days)">
          <AnomaliesPanel orgId={ORG_ID} sinceDays={30} />
        </SectionCard>
      </div>
    </>
  )
}

interface InsightsHeaderControlsProps {
  windowDays: WindowDays
  severity: SeverityFilter
  onWindowChange: (w: WindowDays) => void
  onSeverityChange: (s: SeverityFilter) => void
}

function InsightsHeaderControls({ windowDays, severity, onWindowChange, onSeverityChange }: InsightsHeaderControlsProps) {
  const WINDOW_OPTIONS: { label: string; value: WindowDays }[] = [
    { label: "7d", value: 7 },
    { label: "30d", value: 30 },
    { label: "90d", value: 90 },
  ]
  const SEVERITY_OPTIONS: { label: string; value: SeverityFilter }[] = [
    { label: "All", value: "all" },
    { label: "Critical", value: "critical" },
    { label: "High", value: "high" },
    { label: "Medium", value: "medium" },
    { label: "Low", value: "low" },
  ]
  return (
    <>
      <ChipGroup options={WINDOW_OPTIONS} value={windowDays} onChange={onWindowChange} ariaLabel="Time window" />
      <ChipGroup options={SEVERITY_OPTIONS} value={severity} onChange={onSeverityChange} ariaLabel="Filter by severity" />
    </>
  )
}

function ChipGroup<T extends string | number>({
  options,
  value,
  onChange,
  ariaLabel,
}: {
  options: ReadonlyArray<{ label: string; value: T }>
  value: T
  onChange: (v: T) => void
  ariaLabel: string
}) {
  return (
    <div className="flex items-center rounded-lg border border-[var(--color-border)] overflow-hidden" role="radiogroup" aria-label={ariaLabel}>
      {options.map((opt, i) => (
        <button
          key={String(opt.value)}
          type="button"
          role="radio"
          aria-checked={value === opt.value}
          onClick={() => onChange(opt.value)}
          className={[
            "px-3 py-1.5 text-xs font-semibold transition-colors",
            i < options.length - 1 ? "border-r border-[var(--color-border)]" : "",
            value === opt.value
              ? "bg-[var(--color-accent)] text-[var(--color-accent-on)]"
              : "bg-[var(--color-surface)] text-[var(--color-text-secondary)] hover:bg-[var(--color-surface-raised)] hover:text-[var(--color-text-primary)]",
          ]
            .filter(Boolean)
            .join(" ")}
        >
          {opt.label}
        </button>
      ))}
    </div>
  )
}
