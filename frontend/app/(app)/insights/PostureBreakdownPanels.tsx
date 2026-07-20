"use client"

import Link from "next/link"

import type {
  PostureSnapshotResponse,
  PostureTopRepository,
  PostureAgeBucket,
} from "@/lib/client/posture-api"
import { Card } from "@/components/ui/Card"
import { findingsHref } from "./posture-links"

// Ordinal ramp for adjacent chart fills (donut arcs + legend dots) — one warm
// family ordered by lightness so rank reads without a legend lookup.
const RAMP_VARS = {
  critical: "var(--color-sev-ramp-critical)",
  high: "var(--color-sev-ramp-high)",
  medium: "var(--color-sev-ramp-medium)",
  low: "var(--color-sev-ramp-low)",
  unrated: "var(--color-text-tertiary)",
}

export function SeverityDonut({ snap }: { snap: PostureSnapshotResponse }) {
  const counts = snap.counts
  if (counts.total === 0) return null

  // Include the "unrated" (unknown-severity) slice so the wedges sum to 100%
  // of open findings instead of silently omitting them.
  const segments = (["critical", "high", "medium", "low", "unrated"] as const)
    .map((key) => ({ key, value: key === "unrated" ? counts.unknown : counts[key] }))
    .filter((s) => s.value > 0)

  const r = 45
  const stroke = 7
  const circ = 2 * Math.PI * r
  // Small visual gap between adjacent arcs for a segmented instrument look.
  // Skipped when there's only one arc (a lone slice needs no separator).
  const gap = segments.length > 1 ? 4 : 0

  const segmentsWithOffsets = segments.map((seg, i, arr) => {
    const frac = seg.value / counts.total
    const full = frac * circ
    return {
      ...seg,
      // Never shrink below zero for tiny slices.
      dashLen: Math.max(full - gap, 0.5),
      dashOffset: -arr.slice(0, i).reduce((sum, s) => sum + s.value / counts.total, 0) * circ,
    }
  })

  const critShare = Math.round(((counts.critical + counts.high) / counts.total) * 100)

  return (
    <Card className="rounded-md">
      <h2 className="font-mono text-[11px] font-semibold uppercase tracking-[0.22em] text-[var(--color-text-secondary)]">
        Severity breakdown
      </h2>
      <div className="mt-4 flex items-center gap-6">
        <div className="relative shrink-0">
          <svg
            width="112"
            height="112"
            viewBox="0 0 112 112"
            role="img"
            aria-label={`${counts.critical} critical, ${counts.high} high, ${counts.medium} medium, ${counts.low} low, ${counts.unknown} unrated`}
          >
            <circle
              cx="56"
              cy="56"
              r={r}
              fill="none"
              stroke="var(--color-surface-raised)"
              strokeWidth={stroke}
            />
            {segmentsWithOffsets.map((seg, i) => (
              <circle
                key={seg.key}
                cx="56"
                cy="56"
                r={r}
                fill="none"
                stroke={RAMP_VARS[seg.key]}
                strokeWidth={stroke}
                strokeOpacity={0.9}
                strokeDasharray={`${seg.dashLen} ${circ - seg.dashLen}`}
                strokeDashoffset={seg.dashOffset}
                strokeLinecap="butt"
                transform="rotate(-90 56 56)"
                className="chart-fade"
                style={{ animationDelay: `${i * 80}ms` }}
              >
                <title>{`${seg.key}: ${seg.value.toLocaleString()} (${Math.round((seg.value / counts.total) * 100)}%)`}</title>
              </circle>
            ))}
          </svg>
          <span className="absolute inset-0 flex flex-col items-center justify-center">
            <span className="text-2xl font-semibold leading-none tabular-nums text-[var(--color-text-primary)]">
              {counts.total.toLocaleString()}
            </span>
            <span className="mt-0.5 text-2xs font-mono font-medium uppercase tracking-[0.14em] text-[var(--color-text-tertiary)]">
              open
            </span>
          </span>
        </div>
        <div className="flex flex-col gap-1">
          {segments.map((seg) => (
            <Link
              key={seg.key}
              href={seg.key === "unrated" ? findingsHref({ state: "open" }) : findingsHref({ severity: seg.key, state: "open" })}
              aria-label={`View ${seg.key} findings`}
              className="group -mx-2 flex items-center gap-2 rounded-md px-2 py-1 text-xs transition-colors hover:bg-[var(--color-surface-raised)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-[var(--color-accent)]"
            >
              <span
                className="h-1.5 w-1.5 rounded-full"
                style={{ background: RAMP_VARS[seg.key] }}
                aria-hidden="true"
              />
              <span className="min-w-[52px] capitalize text-[var(--color-text-secondary)]">
                {seg.key}
              </span>
              <span className="tabular-nums font-semibold text-[var(--color-text-primary)]">
                {seg.value.toLocaleString()}
              </span>
              <span className="text-[var(--color-text-tertiary)]">
                {Math.round((seg.value / counts.total) * 100)}%
              </span>
            </Link>
          ))}
        </div>
      </div>
      {counts.critical + counts.high > 0 && (
        <p className="mt-3 border-t border-[var(--color-border)] pt-2.5 text-2xs text-[var(--color-text-tertiary)]">
          <span className="font-semibold text-[var(--color-text-secondary)] tabular-nums">{critShare}%</span>{" "}
          of open findings are high or critical severity
        </p>
      )}
    </Card>
  )
}


export function TopReposPanel({ repos }: { repos: PostureTopRepository[] }) {
  if (repos.length === 0) return null
  const maxOpen = Math.max(...repos.map((r) => r.open), 1)
  return (
    <Card className="rounded-md">
      <h2 className="font-mono text-[11px] font-semibold uppercase tracking-[0.22em] text-[var(--color-text-secondary)]">
        Top repositories by findings
      </h2>
      <div className="mt-4 space-y-1">
        {repos.map((repo, i) => (
          <Link
            key={repo.name}
            href={findingsHref({ repo: repo.name, state: "open" })}
            aria-label={`View findings in ${repo.name}`}
            className="-mx-2 block rounded-md px-2 py-1.5 transition-colors hover:bg-[var(--color-surface-raised)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-[var(--color-accent)]"
          >
            <div className="flex items-center justify-between mb-1">
              <span className="flex min-w-0 items-baseline gap-2">
                <span className="font-mono text-2xs tabular-nums text-[var(--color-text-tertiary)]" aria-hidden="true">
                  {String(i + 1).padStart(2, "0")}
                </span>
                <span
                  className="text-xs font-medium text-[var(--color-text-primary)] truncate max-w-[200px]"
                  title={repo.name}
                >
                  {repo.name}
                </span>
              </span>
              <span className="flex items-center gap-3 text-[11px] tabular-nums shrink-0">
                {repo.critical > 0 && (
                  <span className="flex items-center gap-1 text-[var(--color-text-secondary)]">
                    <span
                      className="h-1.5 w-1.5 rounded-full"
                      style={{ background: "var(--color-sev-ramp-critical)" }}
                      aria-hidden="true"
                    />
                    {repo.critical}
                  </span>
                )}
                <span className="text-[var(--color-text-tertiary)]">{repo.open} open</span>
              </span>
            </div>
            <div
              className="h-1.5 origin-left overflow-hidden rounded-[2px] bg-[var(--color-surface-raised)] chart-bar-grow"
              style={{ width: `${Math.max((repo.open / maxOpen) * 100, 8)}%`, animationDelay: `${i * 50}ms` }}
            >
              <span className="block h-full" style={{ background: "var(--color-border-strong)" }} />
            </div>
          </Link>
        ))}
      </div>
    </Card>
  )
}


export function RepositoryCoveragePanel({ snap }: { snap: PostureSnapshotResponse }) {
  const { repositoryCoverage: cov } = snap
  return (
    <Card className="rounded-md">
      <h2 className="font-mono text-[11px] font-semibold uppercase tracking-[0.22em] text-[var(--color-text-secondary)]">
        Affected repositories
      </h2>
      <div className="mt-4 flex flex-wrap items-end gap-6">
        <div>
          <span className="text-2xl font-semibold leading-none tabular-nums text-[var(--color-text-primary)]">
            {Math.round(cov.percentage)}%
          </span>
          <p className="mt-1 text-[11px] font-mono font-semibold uppercase tracking-[0.22em] text-[var(--color-text-tertiary)]">
            of {cov.total} repos
          </p>
        </div>
        <div>
          <span className="text-2xl font-semibold leading-none tabular-nums text-[var(--color-text-primary)]">
            {cov.affected}
          </span>
          <p className="mt-1 text-[11px] font-mono font-semibold uppercase tracking-[0.22em] text-[var(--color-text-tertiary)]">
            with open findings
          </p>
        </div>
        <div>
          <span className="text-2xl font-semibold leading-none tabular-nums text-[var(--color-text-primary)]">
            {cov.unaffected}
          </span>
          <p className="mt-1 text-[11px] font-mono font-semibold uppercase tracking-[0.22em] text-[var(--color-text-tertiary)]">
            no open findings
          </p>
        </div>
      </div>
      <p className="mt-3 text-2xs text-[var(--color-text-tertiary)]">
        Counts repos with open findings. A repo not yet scanned shows as having no open findings.
      </p>
    </Card>
  )
}


export function AgeBucketsPanel({ buckets }: { buckets: PostureAgeBucket[] }) {
  const total = buckets.reduce((sum, b) => sum + b.count, 0)
  if (total === 0) return null
  const maxCount = Math.max(...buckets.map((b) => b.count), 1)
  // The bucket labels already name each age band, so colour is redundant here.
  // Bars stay neutral; a single accent flags only the oldest (>90d) band —
  // the one that actually needs attention.
  const oldestIdx = buckets.length - 1
  return (
    <Card className="rounded-md">
      <h2 className="font-mono text-[11px] font-semibold uppercase tracking-[0.22em] text-[var(--color-text-secondary)]">
        Finding age distribution
      </h2>
      <div className="mt-4 space-y-2.5">
        {buckets.map((bucket, i) => {
          const tone =
            i === oldestIdx && bucket.count > 0
              ? "var(--color-sev-ramp-critical)"
              : "var(--color-text-tertiary)"
          const pct = (bucket.count / maxCount) * 100
          return (
            <div key={bucket.label} className="flex items-center gap-3">
              <span className="min-w-[64px] text-right text-[11px] tabular-nums text-[var(--color-text-tertiary)]">
                {bucket.label}
              </span>
              <div className="h-2 flex-1 overflow-hidden rounded-[2px] bg-[var(--color-surface-raised)]">
                <div
                  className="h-full origin-left rounded-[2px] chart-bar-grow"
                  title={`${bucket.label}: ${bucket.count.toLocaleString()}`}
                  style={{
                    width: `${Math.max(pct, bucket.count > 0 ? 3 : 0)}%`,
                    background: tone,
                    animationDelay: `${i * 60}ms`,
                  }}
                />
              </div>
              <span className="min-w-[32px] text-xs tabular-nums font-medium text-[var(--color-text-primary)]">
                {bucket.count.toLocaleString()}
              </span>
            </div>
          )
        })}
      </div>
      {buckets.length >= 4 && buckets[3].count > 0 && (
        <p className="mt-3 text-[11px] text-[var(--color-severity-critical-text)]">
          {buckets[3].count.toLocaleString()} findings are over 90 days old
        </p>
      )}
    </Card>
  )
}
