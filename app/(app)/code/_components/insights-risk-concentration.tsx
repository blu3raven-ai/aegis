"use client"

import type { GqlCodeScanningAnalytics } from "@/lib/shared/graphql/types"

const SEV_COLOURS: Record<string, string> = {
  critical: "bg-red-500",
  high: "bg-orange-500",
  medium: "bg-amber-400",
  low: "bg-blue-400",
}

const AGE_BUCKET_COLOUR: Record<string, string> = {
  "< 7 days": "bg-blue-400",
  "7–30 days": "bg-amber-400",
  "30–90 days": "bg-orange-500",
  "> 90 days": "bg-red-500",
}

const AGE_BUCKET_TEXT: Record<string, string> = {
  "< 7 days": "text-blue-400",
  "7–30 days": "text-amber-400",
  "30–90 days": "text-orange-400",
  "> 90 days": "text-red-400",
}

export function InsightsRiskConcentration({
  analytics,
  onGoToFindings,
}: {
  analytics: GqlCodeScanningAnalytics | null
  onGoToFindings: (opts: { repo?: string; ageBucket?: string }) => void
}) {
  const topRepos = analytics?.topRepositories ?? []
  const categories = analytics?.categoryBreakdown ?? []
  const ageBuckets = analytics?.ageBuckets ?? []
  const openCount = analytics?.counts?.total ?? 0

  const isEmpty = openCount === 0

  return (
    <section className="space-y-6">
      <div className="border-t border-[var(--color-border)] pt-12">
        <h2 className="text-2xl font-bold text-[var(--color-text-primary)]">Risk Concentration</h2>
        <p className="mt-1 text-sm text-[var(--color-text-secondary)]">
          Where is risk clustered across repositories, categories, and age?
        </p>
      </div>

      {isEmpty ? (
        <div className="flex min-h-40 items-center justify-center rounded-2xl border border-dashed border-[var(--color-border)] text-sm text-[var(--color-text-secondary)]">
          No open findings to display.
        </div>
      ) : (
        <>
          {/* Top repos + category side by side */}
          <div className="grid gap-5 lg:grid-cols-2">
            {/* Top repos by severity */}
            <div className="rounded-[20px] border border-[var(--color-border)] bg-[var(--color-surface)] p-5">
              <div className="mb-4 flex flex-wrap items-start justify-between gap-3">
                <p className="text-sm font-semibold text-[var(--color-text-primary)]">
                  Open findings by repository
                </p>
                <div className="flex flex-wrap gap-2 text-[11px] text-[var(--color-text-secondary)]">
                  {(["critical", "high", "medium", "low"] as const).map((sev) => (
                    <span key={sev} className="inline-flex items-center gap-1.5">
                      <span className={`h-2 w-2 rounded-full ${SEV_COLOURS[sev]}`} />
                      <span className="capitalize">{sev}</span>
                    </span>
                  ))}
                </div>
              </div>
              <div className="space-y-2">
                {topRepos.length === 0 ? (
                  <p className="text-sm text-[var(--color-text-secondary)]">No open findings.</p>
                ) : (
                  topRepos.map((repo) => {
                    const total = repo.open
                    return (
                      <button
                        key={repo.name}
                        type="button"
                        onClick={() => onGoToFindings({ repo: repo.name })}
                        className="flex w-full items-center gap-3 rounded-lg px-1 py-0.5 text-left transition-colors hover:bg-[var(--color-surface-raised)]"
                      >
                        <span className="w-32 shrink-0 truncate text-right text-xs text-[var(--color-text-secondary)]" title={repo.name}>
                          {repo.name.split("/").pop()}
                        </span>
                        <div className="flex flex-1 overflow-hidden rounded-full bg-[var(--color-border)]" style={{ height: 10 }}>
                          {(["critical", "high"] as const).map((s) => {
                            const pct = total > 0 ? Math.round((repo[s] / total) * 100) : 0
                            if (pct === 0) return null
                            return (
                              <div key={s} className={`h-full ${SEV_COLOURS[s]}`} style={{ width: `${pct}%` }} />
                            )
                          })}
                          {/* remainder as medium+low combined */}
                          {(() => {
                            const remaining = total - repo.critical - repo.high
                            const pct = total > 0 ? Math.round((remaining / total) * 100) : 0
                            if (pct === 0) return null
                            return <div className={`h-full ${SEV_COLOURS.medium}`} style={{ width: `${pct}%` }} />
                          })()}
                        </div>
                        <span className="w-8 text-right text-xs font-semibold text-[var(--color-text-primary)]">{total}</span>
                      </button>
                    )
                  })
                )}
              </div>
            </div>

            {/* Category breakdown */}
            <div className="rounded-[20px] border border-[var(--color-border)] bg-[var(--color-surface)] p-5">
              <p className="mb-4 text-sm font-semibold text-[var(--color-text-primary)]">
                Open findings by category
              </p>
              <div className="space-y-2">
                {categories.length === 0 ? (
                  <p className="text-sm text-[var(--color-text-secondary)]">No open findings.</p>
                ) : (
                  categories.map((cat) => {
                    const pct = openCount > 0 ? Math.round((cat.count / openCount) * 100) : 0
                    return (
                      <div key={cat.category} className="flex items-center gap-3">
                        <span className="w-24 shrink-0 truncate text-right text-xs capitalize text-[var(--color-text-secondary)]">{cat.category}</span>
                        <div className="flex flex-1 overflow-hidden rounded-full bg-[var(--color-border)]" style={{ height: 10 }}>
                          <div className="h-full rounded-full bg-orange-400" style={{ width: `${pct}%` }} />
                        </div>
                        <span className="w-8 text-right text-xs font-semibold text-[var(--color-text-primary)]">{cat.count}</span>
                      </div>
                    )
                  })
                )}
              </div>
            </div>
          </div>

          {/* Age distribution — full width */}
          <div className="rounded-[20px] border border-[var(--color-border)] bg-[var(--color-surface)] p-5">
            <p className="mb-4 text-sm font-semibold text-[var(--color-text-primary)]">
              Open finding age distribution
            </p>
            <p className="mb-4 text-xs text-[var(--color-text-secondary)]">
              Older unresolved findings carry higher risk. Click a bucket to filter findings by age.
            </p>
            <div className="grid gap-3 sm:grid-cols-4">
              {ageBuckets.map((bucket) => (
                <button
                  key={bucket.label}
                  type="button"
                  onClick={() => onGoToFindings({ ageBucket: bucket.label })}
                  className="flex flex-col rounded-2xl border border-[var(--color-border)] bg-[var(--color-surface-raised)] p-4 text-left transition-all hover:border-blue-300"
                >
                  <span className="text-xs text-[var(--color-text-secondary)]">{bucket.label}</span>
                  <span className={`mt-2 text-2xl font-bold tabular-nums ${AGE_BUCKET_TEXT[bucket.label] ?? "text-[var(--color-text-primary)]"}`}>
                    {bucket.count}
                  </span>
                  <div className="mt-2 h-1.5 w-full overflow-hidden rounded-full bg-[var(--color-border)]">
                    <div
                      className={`h-full rounded-full ${AGE_BUCKET_COLOUR[bucket.label] ?? "bg-blue-400"}`}
                      style={{ width: openCount > 0 ? `${Math.round((bucket.count / openCount) * 100)}%` : "0%" }}
                    />
                  </div>
                </button>
              ))}
            </div>
          </div>
        </>
      )}
    </section>
  )
}
