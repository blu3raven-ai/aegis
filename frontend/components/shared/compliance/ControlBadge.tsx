interface ControlBadgeProps {
  framework: string
  controlId: string
  className?: string
}

const FRAMEWORK_COLORS: Record<string, string> = {
  soc2: "bg-[var(--color-accent-subtle)] text-[var(--color-accent)] border-[var(--color-accent-border)]",
  iso27001: "bg-[var(--color-argus-subtle)] text-[var(--color-argus)] border-[var(--color-argus-border)]",
  "pci-dss": "bg-[var(--color-state-fixed-subtle)] text-[var(--color-state-fixed-text)] border-[var(--color-state-fixed-border)]",
}

export function ControlBadge({ framework, controlId, className = "" }: ControlBadgeProps) {
  const colorClass = FRAMEWORK_COLORS[framework] ?? "bg-[var(--color-surface-raised)] text-[var(--color-text-tertiary)] border-[var(--color-border)]"
  return (
    <span
      className={`inline-flex items-center gap-1 rounded border px-1.5 py-0.5 font-mono text-[11px] font-medium ${colorClass} ${className}`}
    >
      {controlId}
    </span>
  )
}
