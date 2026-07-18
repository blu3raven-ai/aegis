"use client"

import type {
  PostureSnapshotResponse,
  PostureTopRepository,
  PostureAgeBucket,
} from "@/lib/client/posture-api"
import { Card } from "@/components/ui/Card"

const SEV_VARS = {
  critical: "var(--color-severity-critical)",
  high: "var(--color-severity-high)",
  medium: "var(--color-severity-medium)",
  low: "var(--color-severity-low)",
}

const SEV_CLASSES = {
  critical: "text-[var(--color-severity-critical)]",
  high: "text-[var(--color-severity-high)]",
  medium: "text-[var(--color-severity-medium)]",
  low: "text-[var(--color-severity-low)]",
}


function SeverityDonut({ snap }: { snap: PostureSnapshotResponse }) {
  const counts = snap.counts
  if (counts.total === 0) return null

  const segments = (["critical", "high", "medium", "low"] as const)
    .map((key) => ({ key, value: counts[key] }))
    .filter((s) => s.value > 0)

  const r = 42
  const stroke = 12
  const circ = 2 * Math.PI * r

  const segmentsWithOffsets = segments.map((seg, i, arr) => ({
    ...seg,
    dashLen: (seg.value / counts.total) * circ,
    dashOffset:
      -arr.slice(0, i).reduce((sum, s) => sum + s.value / counts.total, 0) * circ,
  }))

  return (
    <Card className="rounded-md">
      <p className="font-mono text-[11px] font-semibold uppercase tracking-[0.22em] text-[var(--color-text-secondary)]">
        Severity breakdown
      </p>
      <div className="mt-4 flex items-center gap-6">
        <div className="relative shrink-0">
          <svg
            width="108"
            height="108"
            viewBox="0 0 108 108"
            role="img"
            aria-label={`${counts.critical} critical, ${counts.high} high, ${counts.medium} medium, ${counts.low} low`}
          >
            <circle
              cx="54"
              cy="54"
              r={r}
              fill="none"
              stroke="var(--color-surface-raised)"
              strokeWidth={stroke}
            />
            {segmentsWithOffsets.map((seg) => (
              <circle
                key={seg.key}
                cx="54"
                cy="54"
                r={r}
                fill="none"
                stroke={SEV_VARS[seg.key]}
                strokeWidth={stroke}
                strokeDasharray={`${seg.dashLen} ${circ - seg.dashLen}`}
                strokeDashoffset={seg.dashOffset}
                strokeLinecap="butt"
                transform="rotate(-90 54 54)"
              >
                <title>{`${seg.key}: ${seg.value.toLocaleString()} (${Math.round((seg.value / counts.total) * 100)}%)`}</title>
              </circle>
            ))}
          </svg>
          <span className="absolute inset-0 flex flex-col items-center justify-center">
            <span className="text-xl font-bold tabular-nums text-[var(--color-text-primary)]">
              {counts.total.toLocaleString()}
            </span>
            <span className="text-2xs text-[var(--color-text-tertiary)]">total</span>
          </span>
        </div>
        <div className="flex flex-col gap-2.5">
          {segments.map((seg) => (
            <span key={seg.key} className="flex items-center gap-2 text-xs">
              <span
                className="h-3 w-3 rounded"
                style={{ background: SEV_VARS[seg.key] }}
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
            </span>
          ))}
        </div>
      </div>
    </Card>
  )
}


function TopReposPanel({ repos }: { repos: PostureTopRepository[] }) {
  if (repos.length === 0) return null
  const maxOpen = Math.max(...repos.map((r) => r.open), 1)
  return (
    <Card className="rounded-md">
      <p className="font-mono text-[11px] font-semibold uppercase tracking-[0.22em] text-[var(--color-text-secondary)]">
        Top repositories by findings
      </p>
      <div className="mt-4 space-y-3">
        {repos.map((repo) => (
          <div key={repo.name}>
            <div className="flex items-center justify-between mb-1">
              <span
                className="text-xs font-medium text-[var(--color-text-primary)] truncate max-w-[200px]"
                title={repo.name}
              >
                {repo.name}
              </span>
              <span className="flex items-center gap-2 text-[11px] tabular-nums shrink-0">
                {repo.critical > 0 && (
                  <span className={SEV_CLASSES.critical}>{repo.critical}</span>
                )}
                {repo.high > 0 && <span className={SEV_CLASSES.high}>{repo.high}</span>}
                <span className="text-[var(--color-text-secondary)]">{repo.open}</span>
              </span>
            </div>
            <div
              className="flex h-2 overflow-hidden rounded-full bg-[var(--color-surface-raised)]"
              style={{ width: `${Math.max((repo.open / maxOpen) * 100, 8)}%` }}
            >
              {repo.critical > 0 && (
                <span
                  className="h-full"
                  title={`Critical: ${repo.critical.toLocaleString()}`}
                  style={{
                    width: `${(repo.critical / repo.open) * 100}%`,
                    background: SEV_VARS.critical,
                  }}
                />
              )}
              {repo.high > 0 && (
                <span
                  className="h-full"
                  title={`High: ${repo.high.toLocaleString()}`}
                  style={{
                    width: `${(repo.high / repo.open) * 100}%`,
                    background: SEV_VARS.high,
                  }}
                />
              )}
              {repo.open - repo.critical - repo.high > 0 && (
                <span
                  className="h-full flex-1"
                  title={`Other: ${(repo.open - repo.critical - repo.high).toLocaleString()}`}
                  style={{ background: SEV_VARS.medium, opacity: 0.5 }}
                />
              )}
            </div>
          </div>
        ))}
      </div>
    </Card>
  )
}


function CoverageAndRemediation({ snap }: { snap: PostureSnapshotResponse }) {
  const { repositoryCoverage: cov, remediation: rem } = snap
  return (
    <Card className="rounded-md">
      <p className="font-mono text-[11px] font-semibold uppercase tracking-[0.22em] text-[var(--color-text-secondary)]">
        Repository coverage
      </p>
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
            affected
          </p>
        </div>
        <div>
          <span className="text-2xl font-semibold leading-none tabular-nums text-[var(--color-text-primary)]">
            {cov.unaffected}
          </span>
          <p className="mt-1 text-[11px] font-mono font-semibold uppercase tracking-[0.22em] text-[var(--color-text-tertiary)]">
            clean
          </p>
        </div>
      </div>

      <div className="border-t border-[var(--color-border)] my-4" />

      <p className="font-mono text-[11px] font-semibold uppercase tracking-[0.22em] text-[var(--color-text-secondary)]">
        Remediation (last 90 days)
      </p>
      <div className="mt-4 flex flex-wrap items-end gap-6">
        <div>
          <span className="text-2xl font-semibold leading-none tabular-nums text-[var(--color-text-primary)]">
            {rem.totalFixed.toLocaleString()}
          </span>
          <p className="mt-1 text-[11px] font-mono font-semibold uppercase tracking-[0.22em] text-[var(--color-text-tertiary)]">
            total fixed
          </p>
        </div>
        <div>
          <span className="text-2xl font-semibold leading-none tabular-nums text-[var(--color-text-primary)]">
            {rem.avgDays != null ? `${rem.avgDays}d` : "N/A"}
          </span>
          <p className="mt-1 text-[11px] font-mono font-semibold uppercase tracking-[0.22em] text-[var(--color-text-tertiary)]">
            avg days
          </p>
        </div>
        <div>
          <span className="text-2xl font-semibold leading-none tabular-nums text-[var(--color-text-primary)]">
            {rem.medianDays != null ? `${rem.medianDays}d` : "N/A"}
          </span>
          <p className="mt-1 text-[11px] font-mono font-semibold uppercase tracking-[0.22em] text-[var(--color-text-tertiary)]">
            median days
          </p>
        </div>
        <div>
          <span className="text-2xl font-semibold leading-none tabular-nums text-[var(--color-text-primary)]">
            {rem.fixedLast30d.toLocaleString()}
          </span>
          <p className="mt-1 text-[11px] font-mono font-semibold uppercase tracking-[0.22em] text-[var(--color-text-tertiary)]">
            last 30 days
          </p>
        </div>
      </div>
    </Card>
  )
}


function AgeBucketsPanel({ buckets }: { buckets: PostureAgeBucket[] }) {
  const total = buckets.reduce((sum, b) => sum + b.count, 0)
  if (total === 0) return null
  const maxCount = Math.max(...buckets.map((b) => b.count), 1)
  const ageColors = [
    "var(--color-accent)",
    "var(--color-severity-medium)",
    "var(--color-severity-high)",
    "var(--color-severity-critical)",
  ]
  return (
    <Card className="rounded-md">
      <p className="font-mono text-[11px] font-semibold uppercase tracking-[0.22em] text-[var(--color-text-secondary)]">
        Finding age distribution
      </p>
      <div className="mt-4 space-y-2.5">
        {buckets.map((bucket, i) => (
          <div key={bucket.label} className="flex items-center gap-3">
            <span className="min-w-[64px] text-right text-[11px] tabular-nums text-[var(--color-text-tertiary)]">
              {bucket.label}
            </span>
            <div className="h-5 flex-1 overflow-hidden rounded bg-[var(--color-surface-raised)]">
              <div
                className="h-full rounded"
                title={`${bucket.label}: ${bucket.count.toLocaleString()}`}
                style={{
                  width: `${(bucket.count / maxCount) * 100}%`,
                  background: ageColors[i] ?? ageColors[3],
                  opacity: 0.7,
                }}
              />
            </div>
            <span className="min-w-[32px] text-xs tabular-nums font-medium text-[var(--color-text-primary)]">
              {bucket.count.toLocaleString()}
            </span>
          </div>
        ))}
      </div>
      {buckets.length >= 4 && buckets[3].count > 0 && (
        <p className="mt-3 text-[11px] text-[var(--color-severity-critical)]">
          {buckets[3].count.toLocaleString()} findings are over 90 days old
        </p>
      )}
    </Card>
  )
}


export interface PostureBreakdownTabProps {
  snap: PostureSnapshotResponse
}

export function PostureBreakdownTab({ snap }: PostureBreakdownTabProps) {
  return (
    <div className="px-6 py-5 space-y-5">
      <div className="grid lg:grid-cols-3 gap-5">
        <SeverityDonut snap={snap} />
        <TopReposPanel repos={snap.topRepositories} />
        <CoverageAndRemediation snap={snap} />
      </div>
      {snap.ageBuckets.length > 0 && <AgeBucketsPanel buckets={snap.ageBuckets} />}
    </div>
  )
}
