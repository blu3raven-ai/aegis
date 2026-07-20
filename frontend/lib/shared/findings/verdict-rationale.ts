import type { Verdict } from "@/lib/shared/findings/verdicts"
import type { VerificationMetadata } from "@/lib/shared/findings/row-mapper"

/**
 * A one-line, plain-language explanation of *why* the verifier landed on a
 * non-confirmed verdict — the "is this a false positive?" answer the drawer
 * otherwise leaves implicit.
 *
 * `tone` drives the accent: `neutral` for informational (path not traced,
 * package not imported), `caution` for "we tried to dismiss this but couldn't
 * confirm it, so it stands" (an ungrounded mitigation or unverifiable citation).
 */
export type VerdictRationale = { text: string; tone: "neutral" | "caution" }

/**
 * The verifier records why it couldn't confirm a finding in
 * `verification_metadata`, but the reason never reached the UI. This maps those
 * machine keys to honest, recall-safe prose.
 *
 * Framing rule: a `possible` / `needs_verify` finding is NEVER described as a
 * false positive — the verifier could not confirm it either way, so every
 * message ends at "kept for review", never "dismissed". Only a `ruled_out`
 * verdict (surfaced separately as a confirmed mitigation) means suppressed.
 */
export function verdictRationale(
  verdict: Verdict | null | undefined,
  metadata: VerificationMetadata | null | undefined,
): VerdictRationale | null {
  if (!metadata) return null
  // needs_runtime_verification carries its own concrete question, surfaced
  // separately in the Notes section — no generic FP rationale applies.
  if (
    verdict === "confirmed" ||
    verdict === "ruled_out" ||
    verdict === "needs_runtime_verification"
  )
    return null

  const reason = typeof metadata.reason === "string" ? metadata.reason : ""

  // Order matters: check the most specific / most consequential signal first.
  // A downgraded suppression is the one the analyst most needs to understand —
  // the finding looked mitigated but the mitigation couldn't be verified.
  if (nonEmpty(metadata.suppression_downgraded)) {
    return {
      tone: "caution",
      text:
        "The verifier proposed a mitigation but couldn't confirm it exists in your code, so this finding was not ruled out. Treat it as unverified and review it.",
    }
  }

  if (nonEmpty(metadata.unverified_citations)) {
    return {
      tone: "caution",
      text:
        "The verifier described an exploit path, but some of the code it cited couldn't be confirmed against your repository. Kept for review rather than confirmed.",
    }
  }

  if (nonEmpty(metadata.ungrounded_no_path)) {
    return {
      tone: "caution",
      text:
        "The verifier judged that your code likely doesn't reach this vulnerability, but couldn't cite proof. Kept for review rather than dismissed.",
    }
  }

  if (reason === "package_not_imported") {
    return {
      tone: "neutral",
      text:
        "The vulnerable package isn't imported or referenced anywhere in your code, so there's likely no reachable path. Kept for review, not auto-dismissed.",
    }
  }

  if (reason === "hunter_no_chain") {
    return {
      tone: "neutral",
      text:
        "The verifier couldn't trace an exploit path from user input to this sink. It hasn't confirmed the finding is exploitable, but hasn't ruled it out either.",
    }
  }

  // Both SAST and deps prefix a parse failure with `schema_invalid` /
  // `hunter_schema_invalid` plus the validation error.
  if (reason.startsWith("schema_invalid") || reason.startsWith("hunter_schema_invalid")) {
    return {
      tone: "caution",
      text:
        "The verifier's response couldn't be parsed, so this finding was kept for review rather than automatically confirmed or dismissed.",
    }
  }

  // Grounded reachability signals (deps) that didn't hit a reason branch above.
  const reachability =
    typeof metadata.reachability === "string" ? metadata.reachability : ""
  if (reachability === "reachable") {
    return {
      tone: "caution",
      text:
        "The verifier traced your code reaching this vulnerable dependency. A reachable path is likely, so prioritise it.",
    }
  }
  if (reachability === "no_path") {
    return {
      tone: "neutral",
      text:
        "The verifier found no path from your code to the vulnerable function (its citations checked out), so exploitability is likely low. Kept for review.",
    }
  }

  return null
}

function nonEmpty(v: unknown): boolean {
  return Array.isArray(v) && v.length > 0
}
