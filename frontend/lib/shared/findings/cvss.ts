/**
 * Minimal CVSS v3.x vector parser for the Security Brief. Turns the opaque
 * `CVSS:3.1/AV:N/AC:L/…` string into labelled metrics an analyst can read at a
 * glance, flagging the values that raise exploitability/impact.
 */

export type CvssTone = "danger" | "warn" | "neutral"

export interface CvssMetric {
  /** Short metric name, e.g. "Attack vector". */
  label: string
  /** Decoded value, e.g. "Network". */
  value: string
  /** Severity emphasis for the value (worst → danger). */
  tone: CvssTone
}

type Entry = { label: string; values: Record<string, [string, CvssTone]> }

// Base metrics only — temporal/environmental are rarely populated in feeds.
const BASE_METRICS: Record<string, Entry> = {
  AV: {
    label: "Attack vector",
    values: {
      N: ["Network", "danger"],
      A: ["Adjacent", "warn"],
      L: ["Local", "neutral"],
      P: ["Physical", "neutral"],
    },
  },
  AC: {
    label: "Attack complexity",
    values: { L: ["Low", "warn"], H: ["High", "neutral"] },
  },
  PR: {
    label: "Privileges required",
    values: { N: ["None", "danger"], L: ["Low", "warn"], H: ["High", "neutral"] },
  },
  UI: {
    label: "User interaction",
    values: { N: ["None", "warn"], R: ["Required", "neutral"] },
  },
  S: {
    label: "Scope",
    values: { C: ["Changed", "danger"], U: ["Unchanged", "neutral"] },
  },
  C: {
    label: "Confidentiality",
    values: { H: ["High", "danger"], L: ["Low", "warn"], N: ["None", "neutral"] },
  },
  I: {
    label: "Integrity",
    values: { H: ["High", "danger"], L: ["Low", "warn"], N: ["None", "neutral"] },
  },
  A: {
    label: "Availability",
    values: { H: ["High", "danger"], L: ["Low", "warn"], N: ["None", "neutral"] },
  },
}

// Render order — exploitability metrics first, then impact.
const ORDER = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"]

/**
 * Parse a CVSS v3.x vector into ordered, decoded base metrics. Returns an empty
 * array for a missing/non-v3 vector so callers can simply skip rendering.
 */
export function parseCvssVector(vector: string | null | undefined): CvssMetric[] {
  if (!vector || !/^CVSS:3\.\d/.test(vector.trim())) return []

  const seen: Record<string, string> = {}
  for (const part of vector.trim().split("/")) {
    const [key, val] = part.split(":")
    if (key && val && key in BASE_METRICS) seen[key] = val
  }

  const out: CvssMetric[] = []
  for (const key of ORDER) {
    const code = seen[key]
    if (!code) continue
    const decoded = BASE_METRICS[key].values[code]
    if (!decoded) continue
    out.push({ label: BASE_METRICS[key].label, value: decoded[0], tone: decoded[1] })
  }
  return out
}

// --- CVSS v3.1 base score ---------------------------------------------------
// Official metric weights (CVSS v3.1 specification, section 7.4).

export type CvssSeverity = "None" | "Low" | "Medium" | "High" | "Critical"

export interface CvssScore {
  /** Base score, 0.0–10.0, rounded per the spec. */
  score: number
  /** Qualitative rating derived from the score. */
  severity: CvssSeverity
}

const W_AV: Record<string, number> = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 }
const W_AC: Record<string, number> = { L: 0.77, H: 0.44 }
const W_UI: Record<string, number> = { N: 0.85, R: 0.62 }
const W_CIA: Record<string, number> = { H: 0.56, L: 0.22, N: 0 }
// Privileges Required is weighted differently when Scope is Changed.
const W_PR: Record<"U" | "C", Record<string, number>> = {
  U: { N: 0.85, L: 0.62, H: 0.27 },
  C: { N: 0.85, L: 0.68, H: 0.5 },
}

/** CVSS "Roundup" — round up to one decimal, guarding float error (spec App. A). */
function roundup(input: number): number {
  const intInput = Math.round(input * 100000)
  if (intInput % 10000 === 0) return intInput / 100000
  return (Math.floor(intInput / 10000) + 1) / 10
}

function severityFor(score: number): CvssSeverity {
  if (score <= 0) return "None"
  if (score < 4) return "Low"
  if (score < 7) return "Medium"
  if (score < 9) return "High"
  return "Critical"
}

/**
 * Compute the CVSS v3.1 base score + qualitative rating from a vector string.
 * Returns null for a missing, non-v3, or incomplete-base vector (advisory feeds
 * sometimes carry only the vector, so this recovers the number analysts cite).
 */
export function cvssBaseScore(vector: string | null | undefined): CvssScore | null {
  if (!vector || !/^CVSS:3\.\d/.test(vector.trim())) return null

  const m: Record<string, string> = {}
  for (const part of vector.trim().split("/")) {
    const [k, v] = part.split(":")
    if (k && v) m[k] = v
  }
  if (!["AV", "AC", "PR", "UI", "S", "C", "I", "A"].every((k) => k in m)) return null

  const scope = m.S === "C" ? "C" : "U"
  const av = W_AV[m.AV]
  const ac = W_AC[m.AC]
  const ui = W_UI[m.UI]
  const pr = W_PR[scope][m.PR]
  const c = W_CIA[m.C]
  const i = W_CIA[m.I]
  const a = W_CIA[m.A]
  if ([av, ac, ui, pr, c, i, a].some((x) => x === undefined)) return null

  const iss = 1 - (1 - c) * (1 - i) * (1 - a)
  const impact =
    scope === "U"
      ? 6.42 * iss
      : 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15)
  const exploitability = 8.22 * av * ac * pr * ui

  let score: number
  if (impact <= 0) score = 0
  else if (scope === "U") score = roundup(Math.min(impact + exploitability, 10))
  else score = roundup(Math.min(1.08 * (impact + exploitability), 10))

  return { score, severity: severityFor(score) }
}
