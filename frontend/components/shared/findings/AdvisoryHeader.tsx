import type { ReactNode } from "react"
import type { VerificationMetadata } from "@/lib/shared/findings/row-mapper"

/** Minimal finding shape the advisory header reads — a camelCase structural
 *  subset of `Finding`, so the drawer can pass `selectedFinding` directly. */
export interface AdvisoryHeaderFinding {
  severity: string | null
  repo: string | null
  cwe?: string | null
  cve: string | null
  verificationMetadata?: VerificationMetadata
}

function Row({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="flex gap-3 text-sm">
      <span className="w-24 shrink-0 font-semibold text-[var(--color-text-secondary)]">{label}</span>
      <span className="min-w-0 text-[var(--color-text-primary)]">{children}</span>
    </div>
  )
}

/** Advisory classification header: the formal Target / Severity / CVSS / CWE /
 *  CVE block that leads a security-advisory writeup. Renders nothing when none
 *  of these are known, so lightly-enriched findings don't show an empty block. */
export function AdvisoryHeader({ finding }: { finding: AdvisoryHeaderFinding }) {
  const meta = finding.verificationMetadata ?? {}
  const sev = finding.severity
    ? finding.severity.charAt(0).toUpperCase() + finding.severity.slice(1)
    : null
  if (!finding.repo && !sev && !meta.cvss_vector && !finding.cwe && !finding.cve) {
    return null
  }
  return (
    <section className="space-y-1.5">
      {finding.repo ? <Row label="Target">{finding.repo}</Row> : null}
      {sev ? <Row label="Severity">{sev}</Row> : null}
      {meta.cvss_vector ? (
        <Row label="CVSS 3.1">
          <code className="text-2xs break-all">{meta.cvss_vector}</code>
          {typeof meta.cvss_score === "number" ? (
            <span className="ml-2 font-semibold tabular-nums">{meta.cvss_score}</span>
          ) : null}
        </Row>
      ) : null}
      {finding.cwe ? <Row label="CWE">{finding.cwe}</Row> : null}
      {finding.cve ? <Row label="CVE">{finding.cve}</Row> : null}
    </section>
  )
}
