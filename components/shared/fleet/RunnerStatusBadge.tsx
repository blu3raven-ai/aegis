import type { RunnerStatus } from "@/lib/client/fleet-api"

const STATUS_CONFIG: Record<
  RunnerStatus["status"],
  { dot: string; text: string; label: string }
> = {
  healthy: {
    dot: "bg-[var(--color-status-ok)]",
    text: "text-[var(--color-status-ok)]",
    label: "Healthy",
  },
  degraded: {
    dot: "bg-[var(--color-state-pending)]",
    text: "text-[var(--color-state-pending)]",
    label: "Degraded",
  },
  dead: {
    dot: "bg-[var(--color-text-tertiary)]",
    text: "text-[var(--color-text-tertiary)]",
    label: "Dead",
  },
}

export function RunnerStatusBadge({ status }: { status: RunnerStatus["status"] }) {
  const cfg = STATUS_CONFIG[status] ?? STATUS_CONFIG.dead
  return (
    <span className="inline-flex items-center gap-1.5 text-xs font-medium">
      <span className={`h-2 w-2 rounded-full ${cfg.dot}`} aria-hidden="true" />
      <span className={cfg.text}>{cfg.label}</span>
    </span>
  )
}
