import type { AnalyticsPayload } from "@/lib/shared/dashboard-analytics"
import type { GqlDependenciesAnalytics } from "@/lib/shared/graphql/types"
import type { OpenFindingsFilterOpts } from "@/lib/shared/dependencies/utils"
import { OverviewReviewFocus } from "@/app/(app)/dependencies/_components/overview-review-focus"

// ── Age breakdown bar ──────────────────────────────────────────────────────────

function AgeBucketBar({
  ageBuckets,
  onSelectBucket,
}: {
  ageBuckets: { label: string; count: number }[]
  onSelectBucket: (label: string) => void
}) {
  const total = ageBuckets.reduce((s, b) => s + b.count, 0) || 1
  const COLOURS = ["bg-emerald-400", "bg-amber-400", "bg-orange-400", "bg-red-400", "bg-red-600"]

  return (
    <div className="space-y-2">
      {ageBuckets.map((b, i) => {
        const pct = Math.round((b.count / total) * 100)
        const hasAlerts = b.count > 0
        return (
          <button
            key={b.label}
            type="button"
            disabled={!hasAlerts}
            onClick={() => hasAlerts && onSelectBucket(b.label)}
            className={`flex w-full items-center gap-3 rounded-lg px-1 py-0.5 text-left transition-colors ${hasAlerts ? "cursor-pointer hover:bg-[var(--color-surface-raised)]" : "cursor-default"}`}
          >
            <span className="w-14 shrink-0 text-right text-[11px] text-[var(--color-text-secondary)]">{b.label}</span>
            <div className="flex-1 overflow-hidden rounded-full bg-[var(--color-border)]" style={{ height: 8 }}>
              <div className={`h-full rounded-full transition-all ${COLOURS[i]}`} style={{ width: `${pct}%` }} />
            </div>
            <span className={`w-6 text-right text-xs font-semibold ${hasAlerts ? "text-[var(--color-text-primary)]" : "text-[var(--color-text-secondary)]"}`}>
              {b.count}
            </span>
          </button>
        )
      })}
    </div>
  )
}

// ── Main strip ─────────────────────────────────────────────────────────────────

export function OverviewAttentionStrip({
  analytics,
  activeSeverity,
  onOpenFindingsFiltered,
  entityLabel = "repo",
}: {
  analytics: GqlDependenciesAnalytics | null
  activeSeverity: string
  onOpenFindingsFiltered: (opts: OpenFindingsFilterOpts) => void
  entityLabel?: "repo" | "image"
}) {
  const topRepos = (analytics?.topRepositories ?? []).slice(0, 4)
  const maxRepoOpen = Math.max(...topRepos.map((r) => r.open), 1)
  const ageBuckets = analytics?.ageBuckets ?? []
  const openCount = analytics?.counts.total ?? 0

  return (
    <div className="grid gap-4 xl:grid-cols-3">

      {/* ── Backlog age breakdown ──────────────────────────────────────────── */}
      <div className="flex flex-col rounded-[28px] border border-[var(--color-border)] bg-[var(--color-surface)] p-5 shadow-[0_28px_80px_rgba(15,23,42,0.06)]">
        <p className="text-xs font-semibold uppercase tracking-[0.24em] text-[var(--color-text-secondary)]">Backlog Age</p>
        <h3 className="mt-2 text-xl font-semibold text-[var(--color-text-primary)]">Age Breakdown</h3>
        <p className="mt-0.5 text-xs text-[var(--color-text-secondary)]">
          {openCount} open findings — how long have they been sitting?
        </p>
        <div className="mt-5">
          {openCount === 0 ? (
            <p className="text-sm text-emerald-400">No open findings at this time.</p>
          ) : (
            <AgeBucketBar
              ageBuckets={ageBuckets}
              onSelectBucket={(label) =>
                onOpenFindingsFiltered({ state: "open", ageBucket: label })
              }
            />
          )}
        </div>
        <button
          type="button"
          onClick={() => onOpenFindingsFiltered({ state: "open" })}
          className="mt-5 flex w-full items-center justify-between rounded-2xl border border-[var(--color-border)] bg-[var(--color-surface-raised)] px-4 py-3 text-left transition-colors hover:border-blue-300"
        >
          <span>
            <span className="block text-sm font-semibold text-[var(--color-text-primary)]">
              {openCount} open findings
            </span>
            <span className="text-xs text-[var(--color-text-secondary)]">View all in Findings →</span>
          </span>
        </button>
      </div>

      {/* ── Top repos with gradient bars ──────────────────────────────────── */}
      <div className="flex flex-col rounded-[28px] border border-[var(--color-border)] bg-[var(--color-surface)] p-5 shadow-[0_28px_80px_rgba(15,23,42,0.06)]">
        <p className="text-xs font-semibold uppercase tracking-[0.24em] text-[var(--color-text-secondary)]">Triage Signal</p>
        <h3 className="mt-2 text-xl font-semibold text-[var(--color-text-primary)]">Top {entityLabel === "image" ? "Images" : "Repos"} by Critical/High</h3>
        <p className="mt-0.5 text-xs text-[var(--color-text-secondary)]">
          Click {entityLabel === "image" ? "an image" : "a repo"} to open Findings filtered to its open findings.
        </p>
        <div className="mt-4 space-y-3">
          {topRepos.length === 0 ? (
            <p className="text-sm text-[var(--color-text-secondary)]">No triage data to display yet.</p>
          ) : (
            topRepos.map((repo, idx) => (
              <button
                key={repo.name}
                type="button"
                onClick={() =>
                  onOpenFindingsFiltered({
                    state: "open",
                    repository: repo.name.split("/").pop() ?? repo.name,
                  })
                }
                className="flex w-full flex-col rounded-2xl border border-[var(--color-border)] bg-[var(--color-surface-raised)] px-4 py-3 text-left transition-colors hover:border-blue-300"
              >
                <div className="flex w-full items-center justify-between gap-3">
                  <span className="min-w-0">
                    <span className="flex items-center gap-2">
                      <span className="text-xs font-bold text-[var(--color-text-secondary)]">#{idx + 1}</span>
                      <span className="block truncate text-sm font-semibold text-[var(--color-text-primary)]">
                        {repo.name}
                      </span>
                    </span>
                    <span className="mt-1 block text-xs text-[var(--color-text-secondary)]">
                      {repo.critical} critical · {repo.high} high
                    </span>
                  </span>
                  <span className="shrink-0 text-sm font-semibold text-[var(--color-text-primary)]">
                    {repo.open}
                  </span>
                </div>
                <div className="mt-2 h-2.5 w-full rounded-full bg-[var(--color-surface-raised)]">
                  <div
                    className="h-2.5 rounded-full bg-gradient-to-r from-[var(--color-accent-subtle)] via-[var(--color-accent)] to-cyan-400"
                    style={{ width: `${Math.max((repo.open / maxRepoOpen) * 100, 8)}%` }}
                  />
                </div>
              </button>
            ))
          )}
        </div>
        <button
          type="button"
          onClick={() => onOpenFindingsFiltered({ state: "open" })}
          className="mt-5 flex w-full items-center justify-between rounded-2xl border border-[var(--color-border)] bg-[var(--color-surface-raised)] px-4 py-3 text-left transition-colors hover:border-blue-300"
        >
          <span>
            <span className="block text-sm font-semibold text-[var(--color-text-primary)]">All findings</span>
            <span className="text-xs text-[var(--color-text-secondary)]">View all in Findings →</span>
          </span>
        </button>
      </div>

      {/* ── Review Focus ────────────────────────────────────────────────────── */}
      <div className="flex flex-col rounded-[28px] border border-[var(--color-border)] bg-[var(--color-surface)] p-5 shadow-[0_28px_80px_rgba(15,23,42,0.06)]">
        <OverviewReviewFocus
          analytics={analytics as unknown as AnalyticsPayload | null}
          activeSeverity={activeSeverity}
          onOpenFindingsFiltered={onOpenFindingsFiltered}
        />
      </div>

    </div>
  )
}
