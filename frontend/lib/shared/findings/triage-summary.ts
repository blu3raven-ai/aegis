import type { FindingActionBand, FindingSeverity } from "@/lib/shared/findings/row-mapper"
import type { Verdict } from "@/lib/shared/findings/verdicts"

/**
 * The one-line triage headline shown at the very top of a finding's detail — the
 * "so what?" thesis an analyst reads before scrolling. It fuses the three axes
 * the detail then explains in full: the verdict (is it real?), the action band
 * (how urgent?), and the base severity / KEV context (how bad?).
 *
 * It is deliberately terse — the fuller "how severe really" and "why this
 * verdict" sentences live below it (`severityContext`, `verdictRationale`), so
 * this stays a headline, not a repeat.
 */
export type TriageSummary = {
  text: string
  tone: "danger" | "caution" | "neutral" | "positive"
}

const VERDICT_HEADLINE: Record<Verdict, string> = {
  confirmed: "Confirmed",
  needs_runtime_verification: "Needs runtime check",
  needs_verify: "Needs review",
  possible: "Unconfirmed",
  ruled_out: "Ruled out",
}

const BAND_ACTION: Record<FindingActionBand, string> = {
  act: "act now",
  attend: "attend soon",
  track: "track",
}

export function triageSummary(input: {
  verdict?: Verdict | null
  actionBand?: FindingActionBand | null
  severity?: FindingSeverity | null
  kev?: boolean | null
}): TriageSummary | null {
  const { verdict, actionBand, severity, kev } = input

  // Ruled out is suppressed by a verified mitigation — the action band is moot.
  if (verdict === "ruled_out") {
    return { tone: "positive", text: "Ruled out — a verified mitigation neutralises this finding." }
  }

  // KEV membership leads the qualifier because it's the strongest "how bad" cue.
  const qualifier = kev
    ? `KEV-listed${severity ? ` ${severity}` : ""}`
    : severity
      ? `${severity} severity`
      : ""

  const head = verdict ? VERDICT_HEADLINE[verdict] : ""
  const action = actionBand ? BAND_ACTION[actionBand] : ""
  if (!head && !action) return null

  const tone: TriageSummary["tone"] =
    actionBand === "act" ? "danger" : actionBand === "attend" ? "caution" : "neutral"

  let text: string
  if (head && action) {
    text = `${head} — ${action}${qualifier ? `, ${qualifier}` : ""}.`
  } else if (head) {
    text = `${head}${qualifier ? ` — ${qualifier}` : ""}.`
  } else {
    text = `${capitalise(action)}${qualifier ? `, ${qualifier}` : ""}.`
  }
  return { tone, text }
}

function capitalise(s: string): string {
  return s.charAt(0).toUpperCase() + s.slice(1)
}
