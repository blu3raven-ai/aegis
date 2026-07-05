import type {
  FindingActionBand,
  FindingSeverity,
  Reachability,
} from "@/lib/shared/findings/row-mapper"

/**
 * A one-line, plain-language read on *how severe this finding really is* — the
 * "should I care?" answer that the raw scanner severity alone can't give.
 *
 * It explains the finding's action band (Act / Attend / Track) in terms of the
 * ground-truth signals that produced it: CISA KEV membership (actively exploited
 * in the wild), runner-derived reachability, and the base severity. The band is
 * the backend's source of truth (`findings/action_band.py`); this only narrates
 * the drivers, so the two can't drift.
 *
 * EPSS is intentionally absent: it is never an input to the band (shown as its
 * own chip), so implying it drove the urgency here would be misleading.
 */
export type SeverityContext = { text: string; tone: "danger" | "caution" | "neutral" }

export function severityContext(input: {
  severity?: FindingSeverity | null
  actionBand?: FindingActionBand | null
  kev?: boolean | null
  reachability?: Reachability | null
}): SeverityContext | null {
  const { severity, actionBand, kev, reachability } = input
  if (!actionBand) return null

  const sevLabel = severity ? `${severity} severity` : "its base severity"

  // Act: KEV-listed AND high/critical severity.
  if (actionBand === "act") {
    return {
      tone: "danger",
      text: `On the CISA KEV list — actively exploited in the wild — at ${sevLabel}. Treat as urgent and remediate now.`,
    }
  }

  // Attend: KEV-listed (any severity) OR a reachable path at high/critical.
  if (actionBand === "attend") {
    if (kev) {
      return {
        tone: "caution",
        text: `On the CISA KEV list — actively exploited in the wild — so it warrants prompt attention even at ${sevLabel}.`,
      }
    }
    return {
      tone: "caution",
      text: `${capitalise(sevLabel)} with a call path that reaches the vulnerable code, so it is exploitable here — attend to it soon.`,
    }
  }

  // Track: neither of the above escalations fired. Explain what pulled it down.
  if (reachability === "no_path") {
    return {
      tone: "neutral",
      text: `No call path reaches the vulnerable code, so real-world exploitability is lower than ${sevLabel} alone implies — track it.`,
    }
  }
  if (reachability === "reachable") {
    // Reachable but not escalated ⇒ severity is below high; keep it honest.
    return {
      tone: "neutral",
      text: `The vulnerable code is reachable, but at ${sevLabel} this stays a track-level item — monitor it.`,
    }
  }
  return {
    tone: "neutral",
    text: `Not on the KEV list and no reachable exploit path is confirmed, so it is lower urgency than ${sevLabel} in isolation — track it.`,
  }
}

function capitalise(s: string): string {
  return s.charAt(0).toUpperCase() + s.slice(1)
}
