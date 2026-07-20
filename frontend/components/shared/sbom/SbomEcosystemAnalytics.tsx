"use client"

import { useEffect, useState } from "react"

import { Card } from "@/components/ui/Card"
import { fetchSbomEcosystemAnalytics, type SbomEcosystemAnalytics as EcoRow } from "@/lib/client/sbom-api"

const SEVERITY_ROWS: { key: keyof Pick<EcoRow, "critical" | "high" | "medium" | "low">; label: string; text: string; dot: string }[] = [
  { key: "critical", label: "critical", text: "text-[var(--color-severity-critical-text)]", dot: "bg-[var(--color-severity-critical)]" },
  { key: "high", label: "high", text: "text-[var(--color-severity-high-text)]", dot: "bg-[var(--color-severity-high)]" },
  { key: "medium", label: "medium", text: "text-[var(--color-severity-medium-text)]", dot: "bg-[var(--color-severity-medium)]" },
  { key: "low", label: "low", text: "text-[var(--color-severity-low-text)]", dot: "bg-[var(--color-severity-low)]" },
]

// Risk score is a weighted volume (crit×10, high×5, med×2, low×1). Bucket it so
// the heatmap reads at a glance instead of comparing raw integers.
function riskTone(score: number): string {
  if (score >= 20) return "text-[var(--color-severity-critical-text)]"
  if (score >= 10) return "text-[var(--color-severity-high-text)]"
  if (score >= 3) return "text-[var(--color-severity-medium-text)]"
  if (score > 0) return "text-[var(--color-severity-low-text)]"
  return "text-[var(--color-text-tertiary)]"
}

function ecosystemLabel(eco: string): string {
  if (eco === "") return "Unknown"
  return eco.charAt(0).toUpperCase() + eco.slice(1)
}

export function SbomEcosystemAnalyticsPanel() {
  const [rows, setRows] = useState<EcoRow[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    let cancelled = false
    setLoading(true)
    fetchSbomEcosystemAnalytics()
      .then((data) => {
        if (cancelled) return
        // Worst-risk first so the top of the table is where attention goes.
        const sorted = [...data].sort((a, b) => b.riskScore - a.riskScore || b.totalFindings - a.totalFindings)
        setRows(sorted)
        setError(null)
      })
      .catch(() => {
        if (cancelled) return
        setError("Couldn’t load ecosystem analytics")
      })
      .finally(() => {
        if (!cancelled) setLoading(false)
      })
    return () => {
      cancelled = true
    }
  }, [])

  if (loading) {
    return (
      <Card padding="md" className="space-y-3">
        <div className="h-4 w-48 animate-pulse rounded bg-[var(--color-surface-muted)]" />
        <div className="h-20 w-full animate-pulse rounded bg-[var(--color-surface-muted)]" />
      </Card>
    )
  }

  if (error) {
    return (
      <Card padding="md" className="text-sm text-[var(--color-text-secondary)]">{error}</Card>
    )
  }

  if (rows.length === 0) {
    // Empty scope: no assets the caller can see. Keep the surface quiet rather
    // than 403-ing, matching the list-endpoint empty-result convention.
    return null
  }

  return (
    <Card padding="md" className="space-y-4">
      <div>
        <h2 className="font-mono text-[11px] font-semibold uppercase tracking-[0.22em] text-[var(--color-text-secondary)]">Risk by ecosystem</h2>
        <p className="text-2xs text-[var(--color-text-secondary)]">
          Open dependency findings and SBOM coverage, grouped by package ecosystem across your scope.
        </p>
      </div>

      <div className="overflow-x-auto">
        <table className="w-full border-collapse text-sm">
          <thead>
            <tr className="border-b border-[var(--color-border)] text-left font-mono text-2xs font-semibold uppercase tracking-[0.14em] text-[var(--color-text-tertiary)]">
              <th className="py-2 pr-4 font-semibold">Ecosystem</th>
              <th className="py-2 pr-4 font-semibold">Open findings</th>
              <th className="py-2 pr-4 font-semibold">Risk</th>
              <th className="py-2 pr-4 font-semibold">Components</th>
              <th className="py-2 pr-4 font-semibold">Coverage</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((row) => {
              const visibleSev = SEVERITY_ROWS.filter((s) => row[s.key] > 0)
              return (
                <tr key={row.ecosystem || "__unknown"} className="border-b border-[var(--color-border)] last:border-0">
                  <td className="py-2.5 pr-4">
                    <span className="font-medium text-[var(--color-text-primary)]">{ecosystemLabel(row.ecosystem)}</span>
                    {row.ecosystem === "" && (
                      <span className="ml-2 text-2xs text-[var(--color-text-tertiary)]">no SBOM component</span>
                    )}
                  </td>
                  <td className="py-2.5 pr-4">
                    {visibleSev.length === 0 ? (
                      <span className="text-xs italic text-[var(--color-text-tertiary)]">none</span>
                    ) : (
                      <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
                        {visibleSev.map((s) => (
                          <span key={s.key} className="flex items-center gap-1 text-xs tabular-nums">
                            <span className={`h-1.5 w-1.5 rounded-full ${s.dot}`} aria-hidden="true" />
                            <span className={`font-semibold ${s.text}`}>{row[s.key]}</span>
                            <span className="text-[var(--color-text-secondary)]">{s.label}</span>
                          </span>
                        ))}
                      </div>
                    )}
                  </td>
                  <td className="py-2.5 pr-4">
                    <span className={`font-semibold tabular-nums ${riskTone(row.riskScore)}`}>
                      {row.riskScore}
                    </span>
                  </td>
                  <td className="py-2.5 pr-4 tabular-nums text-[var(--color-text-secondary)]">
                    {row.totalComponents.toLocaleString()}
                  </td>
                  <td className="py-2.5 pr-4">
                    <div className="flex items-center gap-2">
                      <div className="h-1.5 w-20 overflow-hidden rounded-full bg-[var(--color-surface-muted)]" aria-hidden="true">
                        <div
                          className="h-full rounded-full bg-[var(--color-accent)]"
                          style={{ width: `${Math.min(100, Math.round(row.coveragePercentage))}%` }}
                        />
                      </div>
                      <span className="text-xs tabular-nums text-[var(--color-text-secondary)]">
                        {Math.round(row.coveragePercentage)}%
                      </span>
                    </div>
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>

      <p className="text-2xs text-[var(--color-text-tertiary)]">
        Risk = weighted open-finding volume (critical ×10, high ×5, medium ×2, low ×1). Coverage = assets with a component in this ecosystem over the full scope.
      </p>
    </Card>
  )
}
