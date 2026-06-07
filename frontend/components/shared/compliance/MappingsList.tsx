"use client"

import Link from "next/link"
import type { ComplianceFindingBrief } from "@/lib/client/compliance-api"

const SEVERITY_COLORS: Record<string, string> = {
  critical: "bg-[var(--color-severity-critical-subtle)] text-[var(--color-severity-critical)] border-[var(--color-severity-critical-border)]",
  high: "bg-[var(--color-severity-high-subtle)] text-[var(--color-severity-high)] border-[var(--color-severity-high-border)]",
  medium: "bg-[var(--color-severity-medium-subtle)] text-[var(--color-severity-medium)] border-[var(--color-severity-medium-border)]",
  low: "bg-[var(--color-severity-low-subtle)] text-[var(--color-severity-low)] border-[var(--color-severity-low-border)]",
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
}

export function MappingsList({ findings, emptyMessage = "No findings mapped to this control." }: MappingsListProps) {
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
        <div key={finding.id} className="flex items-start justify-between gap-4 py-3">
          <div className="min-w-0 flex-1">
            <Link
              href={`/findings/${finding.id}`}
              className="block truncate text-sm font-medium text-[var(--color-text-primary)] hover:underline"
            >
              {finding.title}
            </Link>
            {finding.scanner_type && (
              <span className="mt-0.5 inline-block text-[11px] text-[var(--color-text-secondary)]">
                {finding.scanner_type}
              </span>
            )}
          </div>
          <div className="shrink-0">
            <SeverityBadge severity={finding.severity} />
          </div>
        </div>
      ))}
    </div>
  )
}
