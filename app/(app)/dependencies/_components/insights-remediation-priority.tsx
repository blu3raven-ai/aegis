import type { OpenFindingsFilterOpts } from "@/lib/shared/dependencies/utils"
import type { GqlRemediationPriorityRow } from "@/lib/shared/graphql/types"

import { SEV_BADGE } from "@/lib/shared/ui/badge-styles"

export function InsightsRemediationPriority({
  remediationPriority,
  onOpenFindingsFiltered,
}: {
  remediationPriority: GqlRemediationPriorityRow[]
  onOpenFindingsFiltered: (opts: OpenFindingsFilterOpts) => void
}) {
  const topRows = remediationPriority.slice(0, 6)

  return (
    <div className="space-y-6">
      {/* Section header */}
      <div className="border-t border-[var(--color-border)] pt-12">
        <h2 className="text-2xl font-bold text-[var(--color-text-primary)]">What to fix first</h2>
        <p className="mt-1 text-sm text-[var(--color-text-secondary)]">
          Vulnerable packages appearing in the most repositories. Fixing these provides the highest impact.
        </p>
      </div>

      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
        {topRows.length === 0 ? (
          <div className="col-span-full rounded-2xl border border-dashed border-[var(--color-border)] p-8 text-center text-sm text-[var(--color-text-secondary)]">
            No open alerts.
          </div>
        ) : (
          topRows.map((row) => (
            <button
              key={`${row.packageName}-${row.ghsaId}`}
              type="button"
              onClick={() => onOpenFindingsFiltered({ state: "open", packageSearch: row.packageName })}
              className="flex flex-col rounded-2xl border border-[var(--color-border)] bg-[var(--color-surface)] p-4 text-left transition-all hover:border-blue-300 hover:shadow-lg"
            >
              <div className="flex items-start justify-between gap-3">
                <div className="min-w-0">
                  <p className="truncate font-semibold text-[var(--color-text-primary)]">
                    {row.packageName}
                  </p>
                  <p className="text-xs text-[var(--color-text-secondary)]">
                    {row.ecosystem}
                  </p>
                </div>
                <span className={`shrink-0 rounded-full px-2 py-0.5 text-2xs font-bold uppercase tracking-wider ${SEV_BADGE[row.severity]}`}>
                  {row.severity}
                </span>
              </div>

              <div className="mt-4 flex items-center justify-between gap-2">
                <span className="text-xs text-[var(--color-text-secondary)]">
                  {row.ghsaId}
                </span>
                <span className="text-xs font-semibold text-[var(--color-accent)]">
                  {row.reposAffected} {row.reposAffected === 1 ? "repo" : "repos"} affected
                </span>
              </div>

              <div className="mt-3 flex items-center justify-between border-t border-[var(--color-border)] pt-3 text-[11px]">
                <span className="text-[var(--color-text-secondary)]">
                  Patch: <span className="font-medium text-[var(--color-state-fixed)]">{row.patchVersion || "None"}</span>
                </span>
                <span className="font-medium text-[var(--color-accent)] group-hover:underline">
                  View alerts →
                </span>
              </div>
            </button>
          ))
        )}
      </div>
    </div>
  )
}
