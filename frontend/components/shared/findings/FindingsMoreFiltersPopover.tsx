import type { FindingActionBand } from "@/lib/shared/findings/row-mapper"

/**
 * Shared shape for the findings filters that aren't first-class controls in the
 * command bar's static catalogue. Consumed by FindingsBoardView (state + URL
 * sync) and FindingsCommandBar (chip rendering).
 */
export interface FindingsMoreFiltersValues {
  cwe: string | null
  kev: boolean
  epssMin: number | null
  bands: FindingActionBand[]
  assigneeUserId: string | null
}
