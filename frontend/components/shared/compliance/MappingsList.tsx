"use client"

import { useState } from "react"
import Link from "next/link"
import { Button } from "@/components/ui/Button"
import { DismissPopover } from "@/components/shared/FindingDrawer/DismissPopover"
import type { ComplianceFindingBrief } from "@/lib/client/compliance-api"

const SUPPRESS_REASONS = [
  "False positive",
  "Not applicable",
  "Compensating control",
  "Accepted risk",
] as const

const SEVERITY_COLORS: Record<string, string> = {
  critical: "bg-[var(--color-severity-critical-subtle)] text-[var(--color-severity-critical-text)] border-[var(--color-severity-critical-border)]",
  high: "bg-[var(--color-severity-high-subtle)] text-[var(--color-severity-high-text)] border-[var(--color-severity-high-border)]",
  medium: "bg-[var(--color-severity-medium-subtle)] text-[var(--color-severity-medium-text)] border-[var(--color-severity-medium-border)]",
  low: "bg-[var(--color-severity-low-subtle)] text-[var(--color-severity-low-text)] border-[var(--color-severity-low-border)]",
}

function SeverityBadge({ severity }: { severity: string }) {
  const colorClass = SEVERITY_COLORS[severity] ?? "bg-[var(--color-bg-hover)] text-[var(--color-text-secondary)] border-[var(--color-border)]"
  return (
    <span
      className={`inline-flex items-center rounded border px-1.5 py-0.5 text-[11px] font-semibold capitalize ${colorClass}`}
    >
      {severity}
    </span>
  )
}

interface MappingsListProps {
  findings: ComplianceFindingBrief[]
  emptyMessage?: string
  /** When set, each mapping gets a suppress/restore control (manage perm). */
  canManage?: boolean
  /** Toggle a mapping's suppression; resolve once the server confirms. */
  onToggleSuppress?: (mappingId: number, suppressed: boolean, reason?: string | null) => Promise<void>
}

function findingTitle(finding: ComplianceFindingBrief): string {
  // Service intentionally omits a free-form title to keep wire size down; the
  // tool + truncated identity key still gives auditors something to pivot on.
  const shortKey = finding.identity_key.length > 80
    ? `${finding.identity_key.slice(0, 80)}…`
    : finding.identity_key
  return `${finding.tool}: ${shortKey}`
}

function findingSourceLabel(finding: ComplianceFindingBrief): string | null {
  if (!finding.org) return null
  return finding.repo ? `${finding.org}/${finding.repo}` : finding.org
}

export function MappingsList({
  findings,
  emptyMessage = "No findings mapped to this control.",
  canManage = false,
  onToggleSuppress,
}: MappingsListProps) {
  if (findings.length === 0) {
    return (
      <div className="flex items-center justify-center py-10 text-sm text-[var(--color-text-secondary)]">
        {emptyMessage}
      </div>
    )
  }

  return (
    <div className="divide-y divide-[var(--color-border)]">
      {findings.map((finding) => (
        <MappingRow
          key={finding.mapping_id}
          finding={finding}
          canManage={canManage}
          onToggleSuppress={onToggleSuppress}
        />
      ))}
    </div>
  )
}

function MappingRow({
  finding,
  canManage,
  onToggleSuppress,
}: {
  finding: ComplianceFindingBrief
  canManage: boolean
  onToggleSuppress?: (mappingId: number, suppressed: boolean, reason?: string | null) => Promise<void>
}) {
  const [busy, setBusy] = useState(false)
  const sourceLabel = findingSourceLabel(finding)

  async function doToggle(suppressed: boolean, reason: string | null) {
    if (!onToggleSuppress) return
    setBusy(true)
    try {
      await onToggleSuppress(finding.mapping_id, suppressed, reason)
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className={`flex items-start justify-between gap-4 py-3 ${finding.suppressed ? "opacity-55" : ""}`}>
      <div className="min-w-0 flex-1">
        <div className="flex items-center gap-2">
          <Link
            href={`/findings?finding=${finding.id}`}
            title={`${finding.tool}: ${finding.identity_key}`}
            className={`truncate text-sm font-medium text-[var(--color-text-primary)] hover:underline ${finding.suppressed ? "line-through" : ""}`}
          >
            {findingTitle(finding)}
          </Link>
          {finding.suppressed && (
            <span className="shrink-0 rounded bg-[var(--color-surface-raised)] px-1.5 py-0.5 font-mono text-[10px] font-semibold uppercase tracking-[0.08em] text-[var(--color-text-tertiary)]">
              Suppressed
            </span>
          )}
        </div>
        {sourceLabel && (
          <span className="mt-0.5 inline-block text-[11px] text-[var(--color-text-secondary)]">
            {sourceLabel}
          </span>
        )}
        {/* Why this finding maps to this control — the auto-mapper's rationale,
            so the link isn't a black box. */}
        {finding.rationale && (
          <p className="mt-1 text-[11px] leading-snug text-[var(--color-text-tertiary)]">
            {finding.rationale}
          </p>
        )}
      </div>
      <div className="flex shrink-0 flex-col items-end gap-1">
        <SeverityBadge severity={finding.severity ?? "info"} />
        {finding.manual ? (
          <span
            title="Mapped manually by an analyst"
            className="rounded bg-[var(--color-accent-subtle)] px-1.5 py-0.5 font-mono text-2xs font-semibold uppercase tracking-[0.08em] text-[var(--color-accent)]"
          >
            Manual
          </span>
        ) : (
          finding.confidence > 0 && (
            <span className="text-[10px] tabular-nums text-[var(--color-text-tertiary)]">
              {Math.round(finding.confidence * 100)}% match
            </span>
          )
        )}
        {canManage && onToggleSuppress && (
          finding.suppressed ? (
            <Button
              variant="ghost"
              size="xs"
              disabled={busy}
              isLoading={busy}
              onClick={() => void doToggle(false, null)}
            >
              Restore
            </Button>
          ) : (
            <DismissPopover
              reasons={SUPPRESS_REASONS}
              isLoading={busy}
              triggerLabel="Suppress"
              placement="bottom"
              onDismiss={(reason) => void doToggle(true, reason)}
            />
          )
        )}
      </div>
    </div>
  )
}
