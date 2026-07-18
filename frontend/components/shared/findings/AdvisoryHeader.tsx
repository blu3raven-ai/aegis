import type { ReactNode } from "react"
import type { VerificationMetadata } from "@/lib/shared/findings/row-mapper"
import { Table, Tbody, Tr, Td } from "@/components/ui/Table"

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
  package?: string | null
  rule?: string | null
  secretDetector?: string | null
}

/** One header row — always rendered; shows a muted "—" when the value is
 *  absent so the report header block is complete for every finding. */
function Row({ label, children }: { label: string; children: ReactNode }) {
  const empty = children == null || children === "" || children === false
  return (
    <Tr>
      <Td className="w-[9.5rem] whitespace-nowrap border-r border-[var(--color-border-divider)] bg-[var(--color-bg-section)] px-3 py-2 align-baseline font-mono text-2xs font-semibold uppercase tracking-[0.1em] text-[var(--color-text-tertiary)]">
        {label}
      </Td>
      <Td
        className={`px-3 py-2 align-baseline text-sm ${empty ? "text-[var(--color-text-tertiary)]" : "text-[var(--color-text-primary)]"}`}
      >
        {empty ? "—" : children}
      </Td>
    </Tr>
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
    <section className="overflow-hidden rounded-md border border-[var(--color-border)]">
      <Table>
        <Tbody divided>
      <Row label="Target">{finding.repo}</Row>
      <Row label="Version affected">{commit}</Row>
      <Row label="Component">{finding.filePath}</Row>
      <Row label="Severity">{sev}</Row>
      <Row label="CVSS 3.1">{cvss}</Row>
      <Row label="CWE">{finding.cwe}</Row>
      <Row label="CVE">{finding.cve}</Row>
      {finding.package ? (
        <Row label="Package">
          <span title={finding.package}>{finding.package}</span>
        </Row>
      ) : null}
      {finding.rule ? (
        <Row label="Rule">
          <span title={finding.rule}>{finding.rule}</span>
        </Row>
      ) : null}
      {finding.secretDetector ? <Row label="Detector">{finding.secretDetector}</Row> : null}
        </Tbody>
      </Table>
    </section>
  )
}
