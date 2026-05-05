import { MetricCard, formatDays, formatCount } from "@/components/shared/MetricCard"

export function SecretsOverviewStatsPanel({
  remediation,
  repositoryCoverage,
}: {
  remediation?: {
    medianDays: number | null
    avgDays: number | null
    fixedLast30d: number
    totalFixed: number
  }
  repositoryCoverage?: {
    percentage: number
    affected: number
    unaffected: number
  }
}) {
  const percentage = repositoryCoverage?.percentage ?? 0
  const affected = repositoryCoverage?.affected ?? 0
  const unaffected = repositoryCoverage?.unaffected ?? 0

  return (
    <div className="grid gap-5 xl:grid-cols-2">

      {/* ── Reach ─────────────────────────────────────────────────────────── */}
      <div className="rounded-[28px] border border-[var(--color-border)] bg-[var(--color-surface)] p-5 shadow-[0_28px_80px_rgba(15,23,42,0.06)]">
        <p className="text-xs font-semibold uppercase tracking-[0.24em] text-[var(--color-text-secondary)]">Reach</p>
        <h3 className="mt-2 text-xl font-semibold text-[var(--color-text-primary)]">Repositories Affected</h3>
        <p className="mt-1 text-xs text-[var(--color-text-secondary)]">How widely the current secrets are spread across the organization.</p>

        <div className="mt-4 rounded-2xl bg-[var(--color-surface-raised)] p-4">
          <p className="text-4xl font-semibold text-[var(--color-text-primary)]">{percentage}%</p>
          <p className="mt-1 text-sm text-[var(--color-text-secondary)]">of active repositories affected</p>

          <div className="mt-4 h-3 overflow-hidden rounded-full bg-[var(--color-border)]">
            <div className="h-full bg-[var(--color-accent)]" style={{ width: `${percentage}%` }} />
          </div>

          <div className="mt-4 grid grid-cols-2 gap-3">
            <div className="rounded-xl border border-[var(--color-border)] bg-[var(--color-surface)] p-3">
              <p className="text-sm text-[var(--color-text-secondary)]">Affected</p>
              <p className="mt-1 text-2xl font-semibold text-[var(--color-text-primary)]">{formatCount(affected)}</p>
            </div>
            <div className="rounded-xl border border-[var(--color-border)] bg-[var(--color-surface)] p-3">
              <p className="text-sm text-[var(--color-text-secondary)]">Unaffected</p>
              <p className="mt-1 text-2xl font-semibold text-[var(--color-text-primary)]">{formatCount(unaffected)}</p>
            </div>
          </div>
        </div>
      </div>

      {/* ── Delivery ──────────────────────────────────────────────────────── */}
      <div className="rounded-[28px] border border-[var(--color-border)] bg-[var(--color-surface)] p-5 shadow-[0_28px_80px_rgba(15,23,42,0.06)]">
        <p className="text-xs font-semibold uppercase tracking-[0.24em] text-[var(--color-text-secondary)]">Delivery</p>
        <h3 className="mt-2 text-xl font-semibold text-[var(--color-text-primary)]">How Fast Secrets Are Being Resolved</h3>

        <div className="mt-5 grid grid-cols-2 gap-3">
          <MetricCard label="Typical resolution time" value={formatDays(remediation?.medianDays)} />
          <MetricCard label="Average resolution time" value={formatDays(remediation?.avgDays)} />
          <MetricCard label="Resolved last 30 days" value={formatCount(remediation?.fixedLast30d)} />
          <MetricCard label="Total resolved (trend basis)" value={formatCount(remediation?.totalFixed)} />
        </div>
      </div>
    </div>
  )
}
