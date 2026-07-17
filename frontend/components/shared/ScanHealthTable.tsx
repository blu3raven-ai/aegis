import { InsightCard } from "@/components/shared/InsightCard"
import { Table, Thead, Tbody, Tr, Th, Td } from "@/components/ui/Table"
import { formatScanTimestamp } from "@/lib/shared/utils"

export interface ScanHealthRun {
  id: string
  status: string
  mode?: string | null
  createdAt?: string | null
  startedAt?: string | null
  finishedAt?: string | null
  durationSeconds?: number | null
  findingsCount?: number | null
  error?: string | null
  progress?: {
    expectedRepos?: number | null
    finishedRepos?: number | null
  } | null
}

const MODE_STYLES: Record<string, string> = {
  light: "bg-[var(--color-accent-subtle)] text-[var(--color-accent)]",
  deep: "bg-[var(--color-argus-subtle)] text-[var(--color-argus)]",
  full: "bg-[var(--color-accent-subtle)] text-[var(--color-accent)]",
  sbom_only: "bg-[var(--color-state-pending-subtle)] text-[var(--color-state-pending-text)]",
  advisories_only: "bg-[var(--color-argus-subtle)] text-[var(--color-argus)]",
}

const MODE_LABELS: Record<string, string> = {
  light: "Light",
  deep: "Deep",
  full: "Full",
  sbom_only: "SBOMs only",
  advisories_only: "Advisories only",
}


function durationLabel(seconds: number | null | undefined) {
  if (typeof seconds !== "number") return "—"
  const m = Math.floor(seconds / 60)
  const s = seconds % 60
  return m > 0 ? `${m}m ${s}s` : `${s}s`
}

function statusColour(status: string) {
  if (status === "completed") return "text-[var(--color-state-fixed-text)]"
  if (status === "failed") return "text-[var(--color-severity-critical-text)]"
  if (status === "cancelled") return "text-[var(--color-text-secondary)]"
  return "text-[var(--color-state-pending-text)]"
}

function ModeBadge({ mode }: { mode?: string | null }) {
  if (!mode) return <span className="text-[var(--color-text-secondary)]">—</span>
  const label = MODE_LABELS[mode] ?? mode.replaceAll("_", " ")
  const style = MODE_STYLES[mode] ?? "bg-[var(--color-surface-raised)] text-[var(--color-text-secondary)]"
  return <span className={`rounded-full px-2 py-0.5 text-xs font-medium ${style}`}>{label}</span>
}

function RunRow({ label, run, showMode }: { label: string; run: ScanHealthRun; showMode: boolean }) {
  const repos = run.progress
    ? `${run.progress.finishedRepos ?? 0} / ${run.progress.expectedRepos ?? "?"}`
    : "—"

  return (
    <Tr
      interactive={run.status !== "failed"}
      className={run.status === "failed" ? "bg-[var(--color-severity-critical-subtle)]" : undefined}
    >
      <Td className="text-xs font-semibold uppercase tracking-[0.22em] text-[var(--color-text-secondary)]">{label}</Td>
      <Td className="text-[var(--color-text-primary)]">{formatScanTimestamp(run.startedAt ?? run.createdAt)}</Td>
      <Td>
        <span className={`capitalize ${statusColour(run.status)}`}>
          {run.status.replaceAll("_", " ")}
        </span>
      </Td>
      {showMode && (
        <Td><ModeBadge mode={run.mode} /></Td>
      )}
      <Td className="text-[var(--color-text-secondary)]">{durationLabel(run.durationSeconds)}</Td>
      <Td className="text-[var(--color-text-secondary)]">{repos}</Td>
      <Td className="text-right font-semibold text-[var(--color-text-primary)]">
        {run.findingsCount ?? "—"}
      </Td>
      {run.error ? (
        <Td className="max-w-xs text-xs text-[var(--color-severity-critical-text)] break-words">{run.error}</Td>
      ) : (
        <Td />
      )}
    </Tr>
  )
}

export function ScanHealthTable({
  runs,
  toolLabel = "scanner",
}: {
  runs: ScanHealthRun[]
  toolLabel?: string
}) {
  const showMode = runs.some((r) => r.mode)
  const colCount = showMode ? 8 : 7

  return (
    <InsightCard
      eyebrow="Scan Health"
      title="Recent scanner runs"
      description={`Status and outcomes of the most recent ${toolLabel} scans.`}
    >
      <div className="overflow-auto rounded-md border border-[var(--color-border)]">
        <Table className="min-w-full">
          <Thead>
            <Tr>
              <Th>Run</Th>
              <Th>Started</Th>
              <Th>Status</Th>
              {showMode && <Th>Mode</Th>}
              <Th>Duration</Th>
              <Th>Repos</Th>
              <Th className="text-right">Findings</Th>
              <Th>Error</Th>
            </Tr>
          </Thead>
          <Tbody>
            {runs.length > 0 ? (
              runs.map((run, i) => (
                <RunRow
                  key={run.id ?? `run-${i}`}
                  label={i === 0 ? "Latest" : `Run ${runs.length - i}`}
                  run={run}
                  showMode={showMode}
                />
              ))
            ) : (
              <Tr>
                <Td colSpan={colCount} className="py-6 text-center text-sm text-[var(--color-text-secondary)]">
                  No scan runs yet.
                </Td>
              </Tr>
            )}
          </Tbody>
        </Table>
      </div>
    </InsightCard>
  )
}
