import Link from "next/link"
import type { ComponentVulns } from "@/lib/client/sbom-api"

const SEV_TIERS = ["critical", "high", "medium", "low"] as const
type SevTier = (typeof SEV_TIERS)[number]

// Text uses the legible `-text` tokens (not the bright fills) so the 10px
// label/count clears WCAG AA on the light *-subtle tints; border/fill unchanged.
const SEV_PILL: Record<SevTier, string> = {
  critical: "border-[var(--color-severity-critical-border)] bg-[var(--color-severity-critical-subtle)] text-[var(--color-severity-critical-text)]",
  high: "border-[var(--color-severity-high-border)] bg-[var(--color-severity-high-subtle)] text-[var(--color-severity-high-text)]",
  medium: "border-[var(--color-severity-medium-border)] bg-[var(--color-severity-medium-subtle)] text-[var(--color-severity-medium-text)]",
  low: "border-[var(--color-severity-low-border)] bg-[var(--color-severity-low-subtle)] text-[var(--color-severity-low-text)]",
}

const NEUTRAL_PILL =
  "border-[var(--color-border)] bg-[var(--color-surface-raised)] text-[var(--color-text-secondary)]"

/** Worst-severity pill with that tier's open-finding count, linking to the
 * package's findings. Renders an em dash when the component has no open
 * vulnerabilities, and a neutral total when only unbucketed (e.g. info) findings
 * are open. Shared by the SBOM explorer and the per-repo components table. */
export function ComponentVulnBadge({
  vulns,
  packageName,
  repo,
}: {
  vulns: ComponentVulns | undefined
  packageName: string
  /** When rendered inside a single repo's SBOM, carry that repo (its
   *  display_name) into the Findings filter so the destination list matches the
   *  count on the badge. Omitted in estate-wide contexts, which stay unscoped. */
  repo?: string
}) {
  if (!vulns || vulns.total === 0) {
    return <span className="text-2xs text-[var(--color-text-tertiary)]">—</span>
  }
  const worst = SEV_TIERS.find((s) => vulns[s] > 0)
  const breakdown =
    SEV_TIERS.filter((s) => vulns[s] > 0).map((s) => `${vulns[s]} ${s}`).join(" · ") ||
    `${vulns.total} open`
  const href =
    `/findings?q=${encodeURIComponent(packageName)}` +
    (repo ? `&repo=${encodeURIComponent(repo)}` : "")
  return (
    <Link
      href={href}
      title={`${breakdown} — view findings`}
      // The visible pill shows only the worst tier; give SR/keyboard users the
      // full per-tier breakdown that's otherwise trapped in the title.
      aria-label={`${packageName}: ${breakdown} open — view findings`}
      className={`inline-flex items-center gap-1 rounded border px-1.5 py-0.5 text-2xs font-semibold tabular-nums ${worst ? SEV_PILL[worst] : NEUTRAL_PILL}`}
    >
      <span className="h-1.5 w-1.5 rounded-full bg-current" aria-hidden />
      {worst ? `${vulns[worst]} ${worst}` : `${vulns.total} open`}
    </Link>
  )
}
