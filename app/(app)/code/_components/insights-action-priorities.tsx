"use client"

import type { GqlCodeScanningAnalytics } from "@/lib/shared/graphql/types"

export function InsightsActionPriorities({
  analytics,
  onGoToFindings,
}: {
  analytics: GqlCodeScanningAnalytics | null
  onGoToFindings: (opts: { ruleId?: string; repo?: string }) => void
}) {
  const topRules = analytics?.topRules ?? []
  const topRepos = analytics?.topRepositories ?? []

  const maxRuleCount = topRules.length > 0 ? topRules[0].count : 1
  const isEmpty = (analytics?.counts?.total ?? 0) === 0

  return (
    <section className="space-y-6">
      <div className="border-t border-[var(--color-border)] pt-12">
        <h2 className="text-base font-semibold text-[var(--color-text-primary)]">Action Priorities</h2>
        <p className="mt-1 text-sm text-[var(--color-text-secondary)]">
          Which rules and repositories should be addressed first?
        </p>
      </div>

      {isEmpty ? (
        <div className="flex min-h-40 items-center justify-center rounded-2xl border border-dashed border-[var(--color-border)] text-sm text-[var(--color-text-secondary)]">
          No open findings to prioritize.
        </div>
      ) : (
        <>
          {/* Top rules bar chart */}
          <div className="rounded-[20px] border border-[var(--color-border)] bg-[var(--color-surface)] p-5">
            <p className="mb-1 text-sm font-semibold text-[var(--color-text-primary)]">Top rules by open finding count</p>
            <p className="mb-4 text-xs text-[var(--color-text-secondary)]">Click a row to filter findings by that rule.</p>
            <div className="space-y-2">
              {topRules.length === 0 ? (
                <p className="text-sm text-[var(--color-text-secondary)]">No open findings.</p>
              ) : (
                topRules.slice(0, 10).map((rule) => {
                  const pct = Math.round((rule.count / maxRuleCount) * 100)
                  const shortName = rule.ruleId.split(".").slice(-2).join(".")
                  return (
                    <button
                      key={rule.ruleId}
                      type="button"
                      onClick={() => onGoToFindings({ ruleId: rule.ruleId })}
                      className="flex w-full items-center gap-3 rounded-lg px-1 py-0.5 text-left transition-colors hover:bg-[var(--color-surface-raised)]"
                    >
                      <div className="w-44 shrink-0 min-w-0">
                        <p className="truncate text-right text-xs font-medium text-[var(--color-text-primary)]" title={rule.ruleName}>{shortName}</p>
                      </div>
                      <div className="flex flex-1 overflow-hidden rounded-full bg-[var(--color-border)]" style={{ height: 10 }}>
                        <div className="h-full rounded-full bg-[var(--color-severity-high)]" style={{ width: `${pct}%` }} />
                      </div>
                      <span className="w-8 text-right text-xs font-semibold text-[var(--color-text-primary)]">{rule.count}</span>
                    </button>
                  )
                })
              )}
            </div>
          </div>

          {/* Top repos for triage — action cards */}
          <div>
            <p className="mb-3 text-sm font-semibold text-[var(--color-text-primary)]">Top repositories for triage</p>
            <p className="mb-4 text-xs text-[var(--color-text-secondary)]">Ranked by critical + high open findings.</p>
            <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
              {topRepos.length === 0 ? (
                <div className="col-span-full rounded-2xl border border-dashed border-[var(--color-border)] p-8 text-center text-sm text-[var(--color-text-secondary)]">
                  No open findings.
                </div>
              ) : (
                topRepos.slice(0, 6).map((repo) => (
                  <button
                    key={repo.name}
                    type="button"
                    onClick={() => onGoToFindings({ repo: repo.name })}
                    className="flex flex-col rounded-2xl border border-[var(--color-border)] bg-[var(--color-surface)] p-4 text-left transition-all hover:border-[var(--color-accent-border)] hover:shadow-lg"
                  >
                    <p className="truncate font-semibold text-[var(--color-text-primary)]" title={repo.name}>
                      {repo.name.split("/").pop()}
                    </p>
                    <p className="mt-0.5 truncate text-xs text-[var(--color-text-secondary)]">{repo.name}</p>
                    <div className="mt-3 flex items-center gap-2">
                      {repo.critical > 0 && (
                        <span className="rounded-full bg-[var(--color-severity-critical-subtle)] px-1.5 py-0.5 text-2xs font-bold text-[var(--color-severity-critical)]">
                          {repo.critical} Critical
                        </span>
                      )}
                      {repo.high > 0 && (
                        <span className="rounded-full bg-[var(--color-severity-high-subtle)] px-1.5 py-0.5 text-2xs font-bold text-[var(--color-severity-high)]">
                          {repo.high} High
                        </span>
                      )}
                    </div>
                    <div className="mt-3 flex items-center justify-between border-t border-[var(--color-border)] pt-3 text-[11px]">
                      <span className="text-[var(--color-text-secondary)]">{repo.open} open findings</span>
                      <span className="font-medium text-[var(--color-accent)]">View findings →</span>
                    </div>
                  </button>
                ))
              )}
            </div>
          </div>
        </>
      )}
    </section>
  )
}
