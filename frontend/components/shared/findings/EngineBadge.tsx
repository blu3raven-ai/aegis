export type Engine = "opengrep" | "joern" | "both"

interface EngineBadgeProps {
  engine: Engine | string | null | undefined
}

const LABELS: Record<Engine, string> = {
  opengrep: "OPENGREP",
  joern: "JOERN",
  both: "JOERN + OPENGREP",
}

/**
 * Pill that surfaces which SAST engine produced a finding. The "both"
 * variant uses solid fill as a high-confidence visual cue — when two
 * independent engines flag the same vulnerability the signal is stronger.
 */
export function EngineBadge({ engine }: EngineBadgeProps) {
  if (!engine || !(engine in LABELS)) return null

  const isBoth = engine === "both"
  const className = isBoth
    ? "inline-flex items-center rounded-full px-2 py-0.5 text-2xs font-semibold uppercase tracking-[0.14em] bg-[var(--color-accent)] text-[var(--color-accent-on)]"
    : "inline-flex items-center rounded-full px-2 py-0.5 text-2xs font-semibold uppercase tracking-[0.14em] bg-[var(--color-accent)]/10 text-[var(--color-accent)]"

  return <span className={className}>{LABELS[engine as Engine]}</span>
}
