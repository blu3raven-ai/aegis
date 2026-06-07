import { baseOsFamily } from "./format"

const FAMILY_STYLES: Record<string, string> = {
  alpine: "bg-[var(--color-severity-low-subtle)] text-[var(--color-severity-low)]",
  debian: "bg-[var(--color-severity-critical-subtle)] text-[var(--color-severity-critical)]",
  ubuntu: "bg-[var(--color-severity-high-subtle)] text-[var(--color-severity-high)]",
  distroless: "bg-[var(--color-state-fixed-subtle)] text-[var(--color-state-fixed)]",
  rhel: "bg-[var(--color-severity-critical-subtle)] text-[var(--color-severity-critical)]",
  centos: "bg-[var(--color-severity-critical-subtle)] text-[var(--color-severity-critical)]",
  amazon: "bg-[var(--color-severity-medium-subtle)] text-[var(--color-severity-medium)]",
  wolfi: "bg-[var(--color-state-fixed-subtle)] text-[var(--color-state-fixed)]",
  chainguard: "bg-[var(--color-state-fixed-subtle)] text-[var(--color-state-fixed)]",
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
