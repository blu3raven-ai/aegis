import type { Verdict } from "@/lib/shared/findings/verdicts"
import { VERDICT_LABEL } from "@/lib/shared/findings/verdicts"

/**
 * Compact, token-driven badge for a finding's Argus-verification verdict.
 * Mirrors the colour language of the VerdictFilterChips so the per-row
 * signal matches the filter the user clicked. Glyph + label keep it
 * legible without relying on colour alone.
 */
const VERDICT_COLOR: Record<Verdict, string> = {
  confirmed: "var(--color-severity-critical)",
  needs_runtime_verification: "var(--color-severity-high)",
  needs_verify: "var(--color-severity-medium)",
  possible: "var(--color-text-tertiary)",
  ruled_out: "var(--color-status-ok)",
}

function VerdictGlyph({ verdict }: { verdict: Verdict }) {
  const cls = "h-2.5 w-2.5 shrink-0"
  if (verdict === "ruled_out") {
    return (
      <svg viewBox="0 0 10 10" className={cls} fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
        <path d="M2 5l2 2 4-5" />
      </svg>
    )
  }
  if (verdict === "possible") {
    return (
      <svg viewBox="0 0 10 10" className={cls} fill="none" stroke="currentColor" strokeWidth="1.5" aria-hidden="true">
        <circle cx="5" cy="5" r="3.5" />
      </svg>
    )
  }
  return (
    <svg viewBox="0 0 10 10" className={cls} fill="currentColor" aria-hidden="true">
      <circle cx="5" cy="5" r="4" />
    </svg>
  )
}

export function VerdictBadge({ verdict }: { verdict: Verdict }) {
  const color = VERDICT_COLOR[verdict]
  return (
    <span
      className="inline-flex shrink-0 items-center gap-1 rounded px-1.5 py-0.5 text-[10px] font-semibold"
      style={{ color, background: `color-mix(in srgb, ${color} 14%, transparent)` }}
      title={`AI verdict: ${VERDICT_LABEL[verdict]}`}
    >
      <VerdictGlyph verdict={verdict} />
      {VERDICT_LABEL[verdict]}
    </span>
  )
}
