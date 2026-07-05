import { baseOsFamily } from "./format"

const FAMILY_STYLES: Record<string, string> = {
  alpine: "bg-[var(--color-severity-low-subtle)] text-[var(--color-severity-low-text)]",
  debian: "bg-[var(--color-severity-critical-subtle)] text-[var(--color-severity-critical-text)]",
  ubuntu: "bg-[var(--color-severity-high-subtle)] text-[var(--color-severity-high-text)]",
  distroless: "bg-[var(--color-state-fixed-subtle)] text-[var(--color-state-fixed-text)]",
  rhel: "bg-[var(--color-severity-critical-subtle)] text-[var(--color-severity-critical-text)]",
  centos: "bg-[var(--color-severity-critical-subtle)] text-[var(--color-severity-critical-text)]",
  amazon: "bg-[var(--color-severity-medium-subtle)] text-[var(--color-severity-medium-text)]",
  wolfi: "bg-[var(--color-state-fixed-subtle)] text-[var(--color-state-fixed-text)]",
  chainguard: "bg-[var(--color-state-fixed-subtle)] text-[var(--color-state-fixed-text)]",
  other: "bg-[var(--color-surface-raised)] text-[var(--color-text-secondary)]",
  unknown: "bg-[var(--color-surface-raised)] text-[var(--color-text-tertiary)]",
}

export function BaseOsChip({ baseOs }: { baseOs: string | null }) {
  const family = baseOsFamily(baseOs)
  const styles = FAMILY_STYLES[family] ?? FAMILY_STYLES.other
  const label = baseOs ?? "unknown base"
  return (
    <span className={`rounded px-1.5 py-0.5 text-2xs font-semibold ${styles}`}>{label}</span>
  )
}
