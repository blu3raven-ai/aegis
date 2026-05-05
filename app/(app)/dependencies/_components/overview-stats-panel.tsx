"use client"
import type { AnalyticsPayload } from "@/lib/shared/dashboard-analytics"

function formatDays(value: number | null | undefined): string {
  if (value == null) return "N/A"
  if (value < 1) return "< 1 day"
  const rounded = Number.isInteger(value) ? value : Math.round(value * 10) / 10
  return `${rounded} ${rounded === 1 ? "day" : "days"}`
}

function formatCount(value: number | null | undefined): string {
  if (value == null) return "—"
  return String(value)
}

function MetricCard({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-2xl bg-[var(--color-surface-raised)] p-4">
      <p className="text-xs font-medium uppercase tracking-[0.10em] text-[var(--color-text-secondary)]">
        {label}
      </p>
      <p className="mt-2 text-2xl font-semibold leading-tight text-[var(--color-text-primary)]">
        {value}
      </p>
    </div>
  )
}

export function OverviewStatsPanel({ analytics, entityLabel = "repo" }: { analytics: AnalyticsPayload | null; entityLabel?: "repo" | "image" }) {
  const coverage = analytics?.repositoryCoverage
  const remediation = analytics?.remediation

  return (
    <div className="grid gap-5 xl:grid-cols-2">
      {/* ── Repository Coverage ─────────────────────────────────────────── */}
      <div className="rounded-[28px] border border-[var(--color-border)] bg-[var(--color-surface)] p-5 shadow-[0_28px_80px_rgba(15,23,42,0.06)]">
        <p className="text-xs font-semibold uppercase tracking-[0.24em] text-[var(--color-text-secondary)]">
          Reach
        </p>
        <h3 className="mt-2 text-xl font-semibold text-[var(--color-text-primary)]">
          {entityLabel === "image" ? "Images" : "Repositories"} Affected
        </h3>
        <p className="mt-1 text-xs text-[var(--color-text-secondary)]">
          How widely the current open issues are spread across the organization.
        </p>

        <div className="mt-4 rounded-2xl bg-[var(--color-surface-raised)] p-4">
          <p className="text-4xl font-semibold text-[var(--color-text-primary)]">
            {coverage ? `${coverage.percentage}%` : "—"}
          </p>
          <p className="mt-1 text-sm text-[var(--color-text-secondary)]">of active {entityLabel === "image" ? "images" : "repositories"} affected</p>

          <div className="mt-4 h-3 overflow-hidden rounded-full bg-[var(--color-border)]">
            <div
              className="h-full bg-[var(--color-accent)]"
              style={{ width: `${coverage?.percentage ?? 0}%` }}
            />
          </div>

          <div className="mt-4 grid grid-cols-2 gap-3">
            <div className="rounded-xl border border-[var(--color-border)] bg-[var(--color-surface)] p-3">
              <p className="text-sm text-[var(--color-text-secondary)]">Affected</p>
              <p className="mt-1 text-2xl font-semibold text-[var(--color-text-primary)]">
                {formatCount(coverage?.affected)}
              </p>
            </div>
            <div className="rounded-xl border border-[var(--color-border)] bg-[var(--color-surface)] p-3">
              <p className="text-sm text-[var(--color-text-secondary)]">Unaffected</p>
              <p className="mt-1 text-2xl font-semibold text-[var(--color-text-primary)]">
                {formatCount(coverage?.unaffected)}
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* ── Delivery Metrics ────────────────────────────────────────────── */}
      <div className="rounded-[28px] border border-[var(--color-border)] bg-[var(--color-surface)] p-5 shadow-[0_28px_80px_rgba(15,23,42,0.06)]">
        <p className="text-xs font-semibold uppercase tracking-[0.24em] text-[var(--color-text-secondary)]">
          Delivery
        </p>
        <h3 className="mt-2 text-xl font-semibold text-[var(--color-text-primary)]">
          How Fast Issues Are Being Closed
        </h3>

        <div className="mt-5 grid grid-cols-2 gap-3">
          <MetricCard label="Typical fix time"           value={formatDays(remediation?.medianDays)} />
          <MetricCard label="Average fix time"           value={formatDays(remediation?.avgDays)} />
          <MetricCard label="Closed last 30 days"        value={formatCount(remediation?.fixedLast30d)} />
          <MetricCard label="Total resolved (trend basis)" value={formatCount(remediation?.totalFixed)} />
        </div>
      </div>
    </div>
  )
}
