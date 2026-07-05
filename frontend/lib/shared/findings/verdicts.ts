/**
 * Shared verdict labels, emoji, and ordering for the Argus-verification
 * filter chips and the EvidenceSection. Mirrors the backend taxonomy
 * (src/findings/service.VALID_VERDICTS + the legacy/all filter aliases).
 */

export type Verdict = "confirmed" | "needs_verify" | "possible" | "ruled_out"
export type VerdictFilter = Verdict | "legacy" | "all" | null

export const VERDICT_LABEL: Record<Verdict, string> = {
  confirmed: "Confirmed",
  needs_verify: "Needs verify",
  possible: "Possible",
  ruled_out: "Ruled out",
}

export const VERDICT_EMOJI: Record<Verdict, string> = {
  confirmed: "🔴",
  needs_verify: "🟡",
  possible: "⚪",
  ruled_out: "✓",
}

/** Highest concern first — useful for sorting groups. */
export const VERDICT_ORDER: Record<Verdict, number> = {
  confirmed: 0,
  needs_verify: 1,
  possible: 2,
  ruled_out: 3,
}

/**
 * Valid `?verdict=` URL / saved-view tokens. `null` (absent) is the default
 * "all open" view, which excludes `ruled_out`; `"all"` disables the filter.
 * Mirrors the backend `_VALID_VERDICT_FILTERS`.
 */
export const VALID_VERDICT_FILTERS = new Set<string>([
  "confirmed", "needs_verify", "possible", "ruled_out", "legacy", "all",
])

/** Parse a raw URL/state token into a VerdictFilter, or null if absent/invalid. */
export function parseVerdictFilter(raw: string | null | undefined): VerdictFilter {
  return raw && VALID_VERDICT_FILTERS.has(raw) ? (raw as VerdictFilter) : null
}
