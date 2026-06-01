import type { RunnerStatus } from "@/lib/client/fleet-api"

function StatPill({
  label,
  count,
  dotClass,
  textClass,
}: {
  label: string
  count: number
  dotClass: string
  textClass: string
}) {
  return (
    <span className="flex items-center gap-1.5 text-sm">
      <span className={`h-2 w-2 rounded-full ${dotClass}`} aria-hidden="true" />
      <span className={`font-semibold tabular-nums ${textClass}`}>
        {count}
      </span>
      <span className="text-[var(--color-text-secondary)]">{label}</span>
    </span>
  )
}

export function FleetSummary({ runners }: { runners: RunnerStatus[] }) {
  const healthy = runners.filter((r) => r.status === "healthy").length
  const degraded = runners.filter((r) => r.status === "degraded").length
  const dead = runners.filter((r) => r.status === "dead").length
  const total = runners.length

  return (
    <div className="rounded-xl border border-[var(--color-border)] bg-[var(--color-surface)] px-5 py-4 shadow-[var(--shadow-card)]">
      <div className="flex flex-col gap-1 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="text-lg font-semibold text-[var(--color-text-primary)]">Runner Fleet</h1>
          <p className="mt-0.5 text-sm text-[var(--color-text-secondary)]">
            Live status of all runner agents in your deployment
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-3 text-sm">
          <StatPill label="Healthy" count={healthy} dotClass="bg-[var(--color-status-ok)]" textClass="text-[var(--color-status-ok)]" />
          <span className="text-[var(--color-border)]">·</span>
          <StatPill label="Degraded" count={degraded} dotClass="bg-[var(--color-state-pending)]" textClass="text-[var(--color-state-pending)]" />
          <span className="text-[var(--color-border)]">·</span>
          <StatPill label="Dead" count={dead} dotClass="bg-[var(--color-text-tertiary)]" textClass="text-[var(--color-text-tertiary)]" />
          <span className="text-[var(--color-border)]">·</span>
          <span className="text-[var(--color-text-secondary)]">
            Total: <strong className="font-semibold text-[var(--color-text-primary)]">{total}</strong>
          </span>
        </div>
      </div>
    </div>
  )
}
