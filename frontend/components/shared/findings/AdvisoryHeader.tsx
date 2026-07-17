import type { ReactNode } from "react"
import type { VerificationMetadata } from "@/lib/shared/findings/row-mapper"

/** Minimal finding shape the advisory header reads — a camelCase structural
 *  subset of `Finding`, so the drawer can pass `selectedFinding` directly. */
export interface AdvisoryHeaderFinding {
  severity?: string | null
  repo?: string | null
  cwe?: string | null
  cve?: string | null
  filePath?: string | null
  introducedByCommit?: string | null
  verificationMetadata?: VerificationMetadata
}

/** One header row — always rendered; shows a muted "—" when the value is
 *  absent so the report header block is complete for every finding. */
function Row({ label, children }: { label: string; children: ReactNode }) {
  const empty = children == null || children === "" || children === false
  return (
    <div className="grid grid-cols-[8.5rem_1fr] items-baseline gap-3 py-2 text-sm">
      <span className="font-mono text-2xs font-semibold uppercase tracking-[0.1em] text-[var(--color-text-tertiary)]">{label}</span>
      <span
        className={`min-w-0 ${empty ? "text-[var(--color-text-tertiary)]" : "text-[var(--color-text-primary)]"}`}
      >
        {empty ? "—" : children}
      </span>
    </div>
  )
}

/** Advisory classification header: the report's Target / Version / Component /
 *  Severity / CVSS / CWE / CVE block. Every row is always present so the header
 *  reads like the report even on a lightly-enriched finding. */
export function AdvisoryHeader({ finding }: { finding: AdvisoryHeaderFinding }) {
  const meta = finding.verificationMetadata ?? {}
  const sev = finding.severity
    ? finding.severity.charAt(0).toUpperCase() + finding.severity.slice(1)
    : null
  const commit = finding.introducedByCommit ? finding.introducedByCommit.slice(0, 10) : null
  const cvss = meta.cvss_vector ? (
    <>
      <code className="text-2xs break-all">{meta.cvss_vector}</code>
      {typeof meta.cvss_score === "number" ? (
        <span className="ml-2 font-semibold tabular-nums">{meta.cvss_score}</span>
      ) : null}
    </>
  ) : null

  return (
    <section className="divide-y divide-[var(--color-border-divider)] border-y border-[var(--color-border-divider)]">
      <Row label="Target">{finding.repo}</Row>
      <Row label="Version affected">{commit}</Row>
      <Row label="Component">{finding.filePath}</Row>
      <Row label="Severity">{sev}</Row>
      <Row label="CVSS 3.1">{cvss}</Row>
      <Row label="CWE">{finding.cwe}</Row>
      <Row label="CVE">{finding.cve}</Row>
    </section>
  )
}
