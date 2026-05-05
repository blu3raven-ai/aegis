import type { OpenFindingsFilterOpts } from "@/lib/shared/dependencies/utils"
import type { GqlEcosystemBreakdownItem, GqlVulnerablePackage } from "@/lib/shared/graphql/types"

// Used for heatmap cells (unchanged) and ecosystem stacked bar segments
const SEV_COLOURS: Record<string, string> = {
  critical: "bg-red-500",
  high:     "bg-orange-500",
  medium:   "bg-amber-400",
  low:      "bg-blue-400",
}

import { SEV_BADGE as SEV_PILL } from "@/lib/shared/ui/badge-styles"

function SeverityLegend() {
  const labels: Record<string, string> = {
    critical: "Critical",
    high: "High",
    medium: "Medium",
    low: "Low",
  }
  return (
    <div className="flex flex-wrap gap-2 text-[11px] text-[var(--color-text-secondary)]">
      {(["critical", "high", "medium", "low"] as const).map((severity) => (
        <span key={severity} className="inline-flex items-center gap-1.5">
          <span className={`h-2 w-2 rounded-full ${SEV_COLOURS[severity]}`} />
          <span>{labels[severity]}</span>
        </span>
      ))}
    </div>
  )
}

export function InsightsRiskConcentration({
  ecosystemBreakdown,
  topVulnerablePackages,
  onOpenFindingsFiltered,
}: {
  ecosystemBreakdown: GqlEcosystemBreakdownItem[]
  topVulnerablePackages: GqlVulnerablePackage[]
  onOpenFindingsFiltered: (opts: OpenFindingsFilterOpts) => void
}) {
  return (
    <div className="space-y-6">
      {/* Section header */}
      <div className="border-t border-[var(--color-border)] pt-12">
        <h2 className="text-2xl font-bold text-[var(--color-text-primary)]">Exposure concentration</h2>
        <p className="mt-1 text-sm text-[var(--color-text-secondary)]">
          Where open vulnerabilities are clustered by ecosystem and reusable package.
        </p>
      </div>

      <div className="grid gap-5 xl:grid-cols-2">
        {/* Ecosystem breakdown — stacked severity bars */}
        <div className="rounded-[20px] border border-[var(--color-border)] bg-[var(--color-surface)] p-5">
          <div className="mb-4 flex flex-wrap items-start justify-between gap-3">
            <p className="text-sm font-semibold text-[var(--color-text-primary)]">
              Open alerts by ecosystem
            </p>
            <SeverityLegend />
          </div>
          <div className="space-y-2">
            {ecosystemBreakdown.length === 0 ? (
              <p className="text-sm text-[var(--color-text-secondary)]">No open alerts.</p>
            ) : (
              ecosystemBreakdown.map((eco) => (
                <button
                  key={eco.ecosystem}
                  type="button"
                  onClick={() => onOpenFindingsFiltered({ state: "open", ecosystem: [eco.ecosystem] })}
                  className="flex w-full items-center gap-3 rounded-lg px-1 py-0.5 text-left transition-colors hover:bg-[var(--color-surface-raised)]"
                >
                  <span className="w-16 shrink-0 truncate text-right text-xs text-[var(--color-text-secondary)]">
                    {eco.ecosystem}
                  </span>
                  <div className="flex flex-1 overflow-hidden rounded-full bg-[var(--color-border)]" style={{ height: 10 }}>
                    {(["critical", "high", "medium", "low"] as const).map((sev) => {
                      const count = eco[sev] ?? 0
                      const pct = eco.total ? Math.round((count / eco.total) * 100) : 0
                      if (pct === 0) return null
                      return (
                        <div
                          key={sev}
                          className={`h-full ${SEV_COLOURS[sev]}`}
                          style={{ width: `${pct}%` }}
                        />
                      )
                    })}
                  </div>
                  <span className="w-8 text-right text-xs font-semibold text-[var(--color-text-primary)]">
                    {eco.total}
                  </span>
                </button>
              ))
            )}
          </div>
        </div>

        {/* Top vulnerable packages — pill style chips */}
        <div className="rounded-[20px] border border-[var(--color-border)] bg-[var(--color-surface)] p-5">
          <p className="mb-4 text-sm font-semibold text-[var(--color-text-primary)]">
            Top vulnerable packages
          </p>
          <div className="max-h-[420px] space-y-2 overflow-y-auto pr-1 [scrollbar-gutter:stable]">
            {topVulnerablePackages.length === 0 ? (
              <p className="text-sm text-[var(--color-text-secondary)]">No vulnerable packages found.</p>
            ) : (
              topVulnerablePackages.map((pkg) => (
                <button
                  key={`${pkg.ecosystem}::${pkg.name}`}
                  type="button"
                  onClick={() => onOpenFindingsFiltered({ state: "open", packageSearch: pkg.name })}
                  className="flex w-full items-center justify-between gap-3 rounded-xl border border-[var(--color-border)] bg-[var(--color-surface-raised)] px-3 py-2 text-left transition-colors hover:border-blue-300"
                >
                  <span className="min-w-0">
                    <span className="block truncate text-sm font-semibold text-[var(--color-text-primary)]">
                      {pkg.name}
                    </span>
                    <span className="text-xs text-[var(--color-text-secondary)]">
                      {pkg.ecosystem} · {pkg.repoCount} repos
                    </span>
                  </span>
                  <span className="flex shrink-0 gap-1">
                    {(["critical", "high", "medium", "low"] as const).map((s) =>
                      pkg[s] > 0 ? (
                        <span
                          key={s}
                          className={`rounded-full px-1.5 py-0.5 text-xs font-semibold ${SEV_PILL[s] ?? ""}`}
                        >
                          {s[0].toUpperCase()} {pkg[s]}
                        </span>
                      ) : null
                    )}
                  </span>
                </button>
              ))
            )}
          </div>
        </div>
      </div>
    </div>
  )
}
