import type { SecretsOverviewFilterOpts } from "@/app/(app)/secrets/_components/overview-kpi-strip"
import { OverviewReviewFocus } from "@/app/(app)/secrets/_components/overview-review-focus"
import type { GqlAgeBucket, GqlSecretsRepoPriority } from "@/lib/shared/graphql/types"

function AgeBucketBar({ buckets, onSelectBucket }: { buckets: GqlAgeBucket[]; onSelectBucket: (label: string) => void }) {
  const total = buckets.reduce((s, b) => s + b.count, 0) || 1
  const COLOURS = [
    "bg-[var(--color-status-ok)]",
    "bg-[var(--color-severity-medium)]",
    "bg-[var(--color-severity-high)]",
    "bg-[var(--color-severity-critical)]",
    "bg-[var(--color-severity-critical)]",
  ]

  return (
    <div className="space-y-2">
      {buckets.map((b, i) => {
        const pct = Math.round((b.count / total) * 100)
        const hasFindings = b.count > 0
        return (
          <button
            key={b.label}
            type="button"
            disabled={!hasFindings}
            onClick={() => hasFindings && onSelectBucket(b.label)}
            className={`flex w-full items-center gap-3 rounded-lg px-1 py-0.5 text-left transition-colors ${hasFindings ? "cursor-pointer hover:bg-[var(--color-surface-raised)]" : "cursor-default"}`}
          >
            <span className="w-14 shrink-0 text-right text-[11px] text-[var(--color-text-secondary)]">{b.label}</span>
            <div className="flex-1 overflow-hidden rounded-full bg-[var(--color-border)]" style={{ height: 8 }}>
              <div className={`h-full rounded-full ${COLOURS[i]} transition-all`} style={{ width: `${pct}%` }} />
            </div>
            <span className={`w-6 text-right text-xs font-semibold ${hasFindings ? "text-[var(--color-text-primary)]" : "text-[var(--color-text-secondary)]"}`}>
              {b.count}
            </span>
          </button>
        )
      })}
    </div>
  )
}

export function OverviewAttentionStrip({
  unresolvedCount,
  ageBuckets,
  triagePriority,
  funnel,
  onOpenReviewFiltered,
}: {
  unresolvedCount: number
  ageBuckets: GqlAgeBucket[]
  triagePriority: GqlSecretsRepoPriority[]
  funnel: {
    newCount: number
    confirmedCount: number
    falsePositiveCount: number
    actionTakenCount: number
  }
  onOpenReviewFiltered: (opts: SecretsOverviewFilterOpts) => void
}) {
  const topRepos = triagePriority.slice(0, 4)

  return (
    <div className="grid gap-4 xl:grid-cols-3">

      {/* ── Age Breakdown ──────────────────────────────────────────────── */}
      <div className="flex flex-col rounded-xl border border-[var(--color-border)] bg-[var(--color-surface)] p-5 shadow-[0_28px_80px_rgba(15,23,42,0.06)]">
        <p className="text-xs font-semibold uppercase tracking-[0.24em] text-[var(--color-text-secondary)]">Backlog Age</p>
        <h3 className="mt-2 text-xl font-semibold text-[var(--color-text-primary)]">Age Breakdown</h3>
        <p className="mt-0.5 text-xs text-[var(--color-text-secondary)]">
          {unresolvedCount} unresolved keys — how long have they been sitting?
        </p>

        <div className="mt-5">
          {unresolvedCount === 0 ? (
            <p className="text-sm text-[var(--color-status-ok)]">All findings have been resolved.</p>
          ) : (
            <AgeBucketBar buckets={ageBuckets} onSelectBucket={(label) => onOpenReviewFiltered({ status: "new", ageBucket: label })} />
          )}
        </div>

        <button
          type="button"
          onClick={() => onOpenReviewFiltered({ status: "new" })}
          className="mt-5 flex w-full items-center justify-between rounded-2xl border border-[var(--color-border)] bg-[var(--color-surface-raised)] px-4 py-3 text-left transition-colors hover:border-[var(--color-accent-border)]"
        >
          <span>
            <span className="block text-sm font-semibold text-[var(--color-text-primary)]">{unresolvedCount} unresolved keys</span>
            <span className="text-xs text-[var(--color-text-secondary)]">View all in Review →</span>
          </span>
        </button>
      </div>

      {/* ── Top Repos ──────────────────────────────────────────────────── */}
      <div className="flex flex-col rounded-xl border border-[var(--color-border)] bg-[var(--color-surface)] p-5 shadow-[0_28px_80px_rgba(15,23,42,0.06)]">
        <p className="text-xs font-semibold uppercase tracking-[0.24em] text-[var(--color-text-secondary)]">Triage Signal</p>
        <h3 className="mt-2 text-xl font-semibold text-[var(--color-text-primary)]">Top Repos by Confirmed Keys</h3>
        <p className="mt-0.5 text-xs text-[var(--color-text-secondary)]">Click a repo to open the Review tab filtered to its confirmed secrets.</p>

        <div className="mt-4 space-y-2">
          {topRepos.length === 0 ? (
            <p className="text-sm text-[var(--color-text-secondary)]">No triage data to display yet.</p>
          ) : (
            topRepos.map((repo, idx) => (
              <button
                key={`${repo.organization}/${repo.repository}`}
                type="button"
                onClick={() => onOpenReviewFiltered({ status: "confirmed", repo: repo.repository })}
                className="flex w-full items-center justify-between gap-3 rounded-2xl border border-[var(--color-border)] bg-[var(--color-surface-raised)] px-4 py-3 text-left transition-colors hover:border-[var(--color-accent-border)]"
              >
                <div className="flex w-full items-center justify-between gap-3">
                  <span className="min-w-0">
                    <span className="flex items-center gap-2">
                      <span className="text-xs font-bold text-[var(--color-text-secondary)]">#{idx + 1}</span>
                      <span className="block truncate text-sm font-semibold text-[var(--color-text-primary)]">
                        {repo.organization}/{repo.repository}
                      </span>
                    </span>
                    <span className="mt-1 block text-xs text-[var(--color-text-secondary)]">
                      {repo.confirmedCount} confirmed keys · needs remediation
                    </span>
                  </span>
                  <span className="shrink-0 rounded-full bg-[var(--color-severity-critical)] px-2.5 py-1 text-xs font-bold tabular-nums text-[var(--color-on-danger)] shadow-[0_4px_12px_rgba(239,68,68,0.35)]">
                    {repo.confirmedCount}
                  </span>
                </div>
              </button>
            ))
          )}
        </div>
        <button
          type="button"
          onClick={() => onOpenReviewFiltered({})}
          className="mt-5 flex w-full items-center justify-between rounded-2xl border border-[var(--color-border)] bg-[var(--color-surface-raised)] px-4 py-3 text-left transition-colors hover:border-[var(--color-accent-border)]"
        >
          <span>
            <span className="block text-sm font-semibold text-[var(--color-text-primary)]">All Findings</span>
            <span className="text-xs text-[var(--color-text-secondary)]">View all in Review →</span>
          </span>
        </button>
      </div>

      {/* ── Review Focus ──────────────────────────────────────────────── */}
      <div className="flex flex-col rounded-xl border border-[var(--color-border)] bg-[var(--color-surface)] p-5 shadow-[0_28px_80px_rgba(15,23,42,0.06)]">
        <OverviewReviewFocus funnel={funnel} onOpenReviewFiltered={onOpenReviewFiltered} />
      </div>

    </div>
  )
}
