/**
 * Dimmed ghost preview rendered when no findings exist and no filters are
 * active. Mock rows mirror the real FindingsBoardView row shape so users see
 * what triage will look like once their first scan reports results.
 *
 * Two shapes:
 *   - Grouped (Findings): rows bucketed by scanner with group headers.
 *   - Flat queue (Inbox): a single newest-first list with no group headers,
 *     mirroring the email-inbox affordance the page advertises.
 */

import { FindingAge } from "@/components/shared/findings/FindingAge"

const SEV_STYLES = {
  critical: "bg-[var(--color-severity-critical)]/10 text-[var(--color-severity-critical-text)]",
  high: "bg-[var(--color-severity-high)]/10 text-[var(--color-severity-high-text)]",
  medium: "bg-[var(--color-severity-medium)]/10 text-[var(--color-severity-medium-text)]",
  low: "bg-[var(--color-severity-low)]/10 text-[var(--color-severity-low-text)]",
} as const

type Severity = keyof typeof SEV_STYLES

interface MockRow {
  severity: Severity
  title: string
  repo: string
  scanner: string
  age: string
  /** Minutes since "now" — drives newest-first ordering for the flat preview. */
  ageMinutes: number
}

const MOCK_GROUPS: Array<{ group: string; rows: MockRow[] }> = [
  {
    group: "Dependencies",
    rows: [
      { severity: "critical", title: "CVE-0000-0000 — example-package", repo: "example-org/frontend", scanner: "Dependencies", age: "2h", ageMinutes: 120 },
      { severity: "high",     title: "Outdated transitive dependency",  repo: "example-org/frontend", scanner: "Dependencies", age: "5h", ageMinutes: 300 },
      { severity: "medium",   title: "Known advisory in lockfile",      repo: "example-org/api",      scanner: "Dependencies", age: "1d", ageMinutes: 60 * 24 },
    ],
  },
  {
    group: "Containers",
    rows: [
      { severity: "high",   title: "Container base image CVE",     repo: "example-org/api", scanner: "Containers", age: "3h", ageMinutes: 180 },
      { severity: "medium", title: "Outdated OS package in image", repo: "example-org/api", scanner: "Containers", age: "2d", ageMinutes: 60 * 24 * 2 },
    ],
  },
  {
    group: "Secrets",
    rows: [
      { severity: "critical", title: "Exposed API key in commit history", repo: "example-org/infra", scanner: "Secrets", age: "1h", ageMinutes: 60 },
    ],
  },
]

function GroupHeader({ label, count }: { label: string; count: number }) {
  return (
    <div className="flex items-center gap-3 border-b border-[var(--color-border)] bg-[var(--color-surface-raised)] px-5 py-2.5">
      <svg className="h-3 w-3 text-[var(--color-text-tertiary)]" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2}>
        <path d="m6 9 6 6 6-6" />
      </svg>
      <span className="text-2xs font-semibold uppercase tracking-[0.14em] text-[var(--color-text-secondary)]">
        {label}
      </span>
      <span className="text-2xs tabular-nums text-[var(--color-text-tertiary)]">{count}</span>
    </div>
  )
}

function Row({ row }: { row: MockRow }) {
  return (
    <div className="flex items-center gap-3 px-5 py-3">
      <span className={`inline-flex shrink-0 items-center gap-1.5 rounded px-2 py-0.5 text-2xs font-semibold uppercase tracking-wide ${SEV_STYLES[row.severity]}`}>
        <span aria-hidden="true" className="inline-block h-1.5 w-1.5 rounded-full bg-current" />
        {row.severity}
      </span>
      <div className="min-w-0 flex-1">
        <div className="truncate text-sm font-medium text-[var(--color-text-primary)]">
          {row.title}
        </div>
        <div className="mt-0.5 flex flex-wrap items-center gap-x-2 text-[11px] text-[var(--color-text-tertiary)]">
          <span>{row.repo}</span>
          <span>·</span>
          <span>{row.scanner}</span>
        </div>
      </div>
      <FindingAge age={row.age} className="shrink-0 text-2xs text-[var(--color-text-tertiary)]" />
    </div>
  )
}

export function FindingsGhostPreview({ flat = false }: { flat?: boolean }) {
  if (flat) {
    // Newest-first flat queue — mirrors the real Inbox shape ("Triage open
    // findings, newest first").
    const rows = MOCK_GROUPS.flatMap((g) => g.rows).sort(
      (a, b) => a.ageMinutes - b.ageMinutes,
    )
    return (
      <div className="divide-y divide-[var(--color-border-divider)]">
        {rows.map((row, idx) => (
          <Row key={`flat-${idx}`} row={row} />
        ))}
      </div>
    )
  }

  return (
    <div className="divide-y divide-[var(--color-border)]">
      {MOCK_GROUPS.map((group) => (
        <div key={group.group}>
          <GroupHeader label={group.group} count={group.rows.length} />
          <div className="divide-y divide-[var(--color-border-divider)]">
            {group.rows.map((row, idx) => (
              <Row key={`${group.group}-${idx}`} row={row} />
            ))}
          </div>
        </div>
      ))}
    </div>
  )
}
