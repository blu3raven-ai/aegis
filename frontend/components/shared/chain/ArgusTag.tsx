"use client"

/**
 * Small gradient pill that marks Argus-enriched fields.
 *
 * Uses --color-accent (cyan) → purple gradient, both already in the palette.
 */
export function ArgusTag() {
  return (
    <span
      className="font-mono inline-block rounded px-1.5 py-px text-[8px] font-bold uppercase tracking-[0.08em] text-[var(--color-accent-on)]"
      style={{ background: "linear-gradient(135deg, var(--color-accent), #c084fc)" }}
    >
      Argus
    </span>
  )
}
