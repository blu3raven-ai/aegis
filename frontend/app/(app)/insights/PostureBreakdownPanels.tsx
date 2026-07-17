"use client"

import Link from "next/link"

import type {
  PostureSnapshotResponse,
  PostureTopRepository,
  PostureAgeBucket,
} from "@/lib/client/posture-api"
import { Card } from "@/components/ui/Card"
import { findingsHref } from "./posture-links"

const SEV_VARS = {
  critical: "var(--color-severity-critical)",
  high: "var(--color-severity-high)",
  medium: "var(--color-severity-medium)",
  low: "var(--color-severity-low)",
  unrated: "var(--color-text-tertiary)",
}

const SEV_CLASSES = {
  critical: "text-[var(--color-severity-critical-text)]",
  high: "text-[var(--color-severity-high-text)]",
  medium: "text-[var(--color-severity-medium-text)]",
  low: "text-[var(--color-severity-low-text)]",
  unrated: "text-[var(--color-text-tertiary)]",
}


// Lighter companion tone per severity, used as the second gradient stop so
// each donut arc reads as a soft sweep rather than a flat band.
const SEV_GRAD_LIGHT = {
  critical: "#f87171",
  high: "#fb923c",
  medium: "#fcd34d",
  low: "#93c5fd",
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

  const r = 42
  const stroke = 13
  const circ = 2 * Math.PI * r
  // Small visual gap between adjacent arcs for a segmented, modern look.
  // Skipped when there's only one arc (a lone slice needs no separator).
  const gap = segments.length > 1 ? 3 : 0

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
      <h2 className="text-base font-semibold text-[var(--color-text-primary)]">
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
            <defs>
              {segments.map((seg) => (
                <linearGradient key={seg.key} id={`donut-${seg.key}`} x1="0" y1="0" x2="1" y2="1">
                  <stop offset="0%" stopColor={SEV_VARS[seg.key]} />
                  <stop offset="100%" stopColor={SEV_GRAD_LIGHT[seg.key]} />
                </linearGradient>
              ))}
            </defs>
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
                stroke={`url(#donut-${seg.key})`}
                strokeWidth={stroke}
                strokeDasharray={`${seg.dashLen} ${circ - seg.dashLen}`}
                strokeDashoffset={seg.dashOffset}
                strokeLinecap="round"
                transform="rotate(-90 56 56)"
                className="chart-fade"
                style={{ animationDelay: `${i * 80}ms` }}
              >
                <title>{`${seg.key}: ${seg.value.toLocaleString()} (${Math.round((seg.value / counts.total) * 100)}%)`}</title>
              </circle>
            ))}
          </svg>
          <span className="absolute inset-0 flex flex-col items-center justify-center">
            <span className="text-2xl font-bold leading-none tabular-nums text-[var(--color-text-primary)]">
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
                className="h-3 w-3 rounded-full ring-2 ring-transparent transition-all group-hover:ring-[var(--color-surface)]"
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
      <h2 className="text-base font-semibold text-[var(--color-text-primary)]">
        Top repositories by findings
      </h2>
      <div className="mt-4 space-y-1">
        {repos.map((repo) => (
          <Link
            key={repo.name}
            href={findingsHref({ repo: repo.name, state: "open" })}
            aria-label={`View findings in ${repo.name}`}
            className="-mx-2 block rounded-md px-2 py-1.5 transition-colors hover:bg-[var(--color-surface-raised)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-[var(--color-accent)]"
          >
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
      <h2 className="text-base font-semibold text-[var(--color-text-primary)]">
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
        Counts repos with open findings — a repo not yet scanned shows as having no open findings.
      </p>
    </Card>
  )
}


export function AgeBucketsPanel({ buckets }: { buckets: PostureAgeBucket[] }) {
  const total = buckets.reduce((sum, b) => sum + b.count, 0)
  if (total === 0) return null
  const maxCount = Math.max(...buckets.map((b) => b.count), 1)
  // Age reads as a heat ramp: fresh (accent blue) → stale (critical red).
  // Each bar is a left-to-right gradient between the tone and a lighter
  // companion so it reads with depth instead of a flat dull band.
  const ageRamp = [
    ["#60a5fa", "var(--color-accent)"],
    ["#fcd34d", "var(--color-severity-medium)"],
    ["#fb923c", "var(--color-severity-high)"],
    ["#f87171", "var(--color-severity-critical)"],
  ]
  return (
    <Card className="rounded-md">
      <h2 className="text-base font-semibold text-[var(--color-text-primary)]">
        Finding age distribution
      </h2>
      <div className="mt-4 space-y-2.5">
        {buckets.map((bucket, i) => {
          const [from, to] = ageRamp[i] ?? ageRamp[3]
          const pct = (bucket.count / maxCount) * 100
          return (
            <div key={bucket.label} className="flex items-center gap-3">
              <span className="min-w-[64px] text-right text-[11px] tabular-nums text-[var(--color-text-tertiary)]">
                {bucket.label}
              </span>
              <div className="h-5 flex-1 overflow-hidden rounded-full bg-[var(--color-surface-raised)]">
                <div
                  className="h-full rounded-full transition-[width] duration-500 ease-out"
                  title={`${bucket.label}: ${bucket.count.toLocaleString()}`}
                  style={{
                    width: `${Math.max(pct, bucket.count > 0 ? 3 : 0)}%`,
                    background: `linear-gradient(90deg, ${from} 0%, ${to} 100%)`,
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
