import type { VulnCounts } from "@/lib/client/sbom-diff-api"

/** Severity tiers, worst-first — the canonical ordering for triage. */
export const SEV_TIERS = ["critical", "high", "medium", "low"] as const

export const SEV_ABBR: Record<(typeof SEV_TIERS)[number], string> = {
  critical: "C",
  high: "H",
  medium: "M",
  low: "L",
}

/** Verbose per-tier breakdown for tooltips (e.g. "2 critical · 3 high"). */
export function breakdown(counts: VulnCounts): string {
  return (
    SEV_TIERS.filter((s) => counts[s] > 0)
      .map((s) => `${counts[s]} ${s}`)
      .join(" · ") || `${counts.total}`
  )
}

/** Compact severity composition for at-a-glance display (e.g. "2C 3H"). A
 * resolved critical must read differently from a resolved low, so the delta is
 * spelled out by tier rather than collapsed to a bare total. Falls back to the
 * total when no per-tier counts are present. */
export function composition(counts: VulnCounts): string {
  const parts = SEV_TIERS.filter((s) => counts[s] > 0).map((s) => `${counts[s]}${SEV_ABBR[s]}`)
  return parts.length > 0 ? parts.join(" ") : `${counts.total}`
}

/** Sum advisory counts per severity tier across a list (undefined entries skipped). */
export function aggregateCounts(counts: (VulnCounts | undefined)[]): VulnCounts {
  const out: VulnCounts = { critical: 0, high: 0, medium: 0, low: 0, total: 0 }
  for (const c of counts) {
    if (!c) continue
    out.critical += c.critical
    out.high += c.high
    out.medium += c.medium
    out.low += c.low
    out.total += c.total
  }
  return out
}

/** Order by severity composition — a single critical outranks any number of
 * lower tiers — so the row that matters most for triage sorts first. Suitable
 * as an Array#sort comparator (descending by severity). */
export function compareSeverity(a: VulnCounts | undefined, b: VulnCounts | undefined): number {
  for (const s of SEV_TIERS) {
    const d = (b?.[s] ?? 0) - (a?.[s] ?? 0)
    if (d !== 0) return d
  }
  return 0
}
