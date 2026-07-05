"use client"

import { useEffect, useMemo, useState } from "react"
import Link from "next/link"

import type {
  ScannerBreakdownItem,
  ExploitabilitySummary,
  SlaPostureSummary,
  RiskContributionItem,
} from "@/lib/client/posture-api"
import { getPostureRiskContributions } from "@/lib/client/posture-api"
import { Card } from "@/components/ui/Card"
import { SegmentedControl } from "@/components/ui/SegmentedControl"
import { findingsHref } from "./posture-links"

// ── Shared severity styling (mirrors SbomEcosystemAnalytics) ────────────────
// The bare severity token is used ONLY for dots/bars — never as text color,
// which fails contrast. Text always uses the -text variant.

type SevKey = "critical" | "high" | "medium" | "low"

const SEV_DOT: Record<SevKey, string> = {
  critical: "bg-[var(--color-severity-critical)]",
  high: "bg-[var(--color-severity-high)]",
  medium: "bg-[var(--color-severity-medium)]",
  low: "bg-[var(--color-severity-low)]",
}

const SEV_TEXT: Record<SevKey, string> = {
  critical: "text-[var(--color-severity-critical-text)]",
  high: "text-[var(--color-severity-high-text)]",
  medium: "text-[var(--color-severity-medium-text)]",
  low: "text-[var(--color-severity-low-text)]",
}

const SEV_BAR: Record<SevKey, string> = {
  critical: "bg-[var(--color-severity-critical)]",
  high: "bg-[var(--color-severity-high)]",
  medium: "bg-[var(--color-severity-medium)]",
  low: "bg-[var(--color-severity-low)]",
}

const SEV_ORDER: SevKey[] = ["critical", "high", "medium", "low"]

const SEV_LABELS: Record<SevKey, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
}

/** Risk-tone for a numeric score, matching the ecosystem-analytics heatmap. */
function riskTone(score: number): string {
  if (score >= 20) return "text-[var(--color-severity-critical-text)]"
  if (score >= 10) return "text-[var(--color-severity-high-text)]"
  if (score >= 3) return "text-[var(--color-severity-medium-text)]"
  if (score > 0) return "text-[var(--color-severity-low-text)]"
  return "text-[var(--color-text-tertiary)]"
}

const SCANNER_LABELS: Record<string, string> = {
  dependencies_scanning: "Dependency Scanning",
  code_scanning: "Code Scanning",
  container_scanning: "Container Scanning",
  secret_scanning: "Secret Scanning",
  iac_scanning: "IaC Scanning",
}

function scannerLabel(tool: string): string {
  return SCANNER_LABELS[tool] ?? tool
}

interface PostureTriageTabProps {
  scannerBreakdown: ScannerBreakdownItem[] | null
  exploitability: ExploitabilitySummary | null
  slaPosture: SlaPostureSummary | null
}

export function PostureTriageTab({
  scannerBreakdown,
  exploitability,
  slaPosture,
}: PostureTriageTabProps) {
  return (
    <div className="space-y-5 px-6 py-5">
      <RiskDecompositionCard />
      <ScannerBreakdownCard rows={scannerBreakdown} />
      <ExploitabilityCard data={exploitability} />
      <SlaPostureCard data={slaPosture} />
    </div>
  )
}

// ── Card 1: Risk decomposition ──────────────────────────────────────────────

const DIMENSIONS = [
  { id: "scanner", label: "Scanner" },
  { id: "repo", label: "Repo" },
  { id: "team", label: "Team" },
  { id: "severity", label: "Severity" },
  { id: "ecosystem", label: "Ecosystem" },
] as const

type Dimension = (typeof DIMENSIONS)[number]["id"]

/**
 * Whether a risk-contribution row for this dimension can drill into the
 * Findings page with a working filter. repo/severity/scanner are read by
 * Findings; team/ecosystem have no matching param and stay display-only.
 */
function dimensionHasFilter(dim: Dimension): dim is "scanner" | "repo" | "severity" {
  return dim === "scanner" || dim === "repo" || dim === "severity"
}

function RiskDecompositionCard() {
  const [dimension, setDimension] = useState<Dimension>("scanner")
  const [rows, setRows] = useState<RiskContributionItem[] | null>(null)

  useEffect(() => {
    let cancelled = false
    setRows(null)
    getPostureRiskContributions(dimension)
      .then((data) => {
        if (!cancelled) setRows(data)
      })
      .catch(() => {
        if (!cancelled) setRows([])
      })
    return () => {
      cancelled = true
    }
  }, [dimension])

  const orgTotal = useMemo(
    () => (rows ? rows.reduce((sum, r) => sum + r.riskScore, 0) : 0),
    [rows],
  )

  return (
    <Card padding="md" className="space-y-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h2 className="text-base font-semibold text-[var(--color-text-primary)]">
            Risk decomposition
          </h2>
          <p className="text-2xs text-[var(--color-text-secondary)]">
            Where your risk concentrates — switch the dimension to re-slice.
          </p>
        </div>
        <SegmentedControl
          ariaLabel="Risk decomposition dimension"
          size="xs"
          value={dimension}
          onChange={(id) => setDimension(id as Dimension)}
          options={DIMENSIONS}
        />
      </div>

      {rows == null ? (
        <div className="space-y-2">
          {[0, 1, 2, 3].map((i) => (
            <div
              key={i}
              className="h-9 w-full animate-pulse rounded bg-[var(--color-surface-muted)]"
            />
          ))}
        </div>
      ) : rows.length === 0 ? (
        <p className="py-6 text-center text-sm text-[var(--color-text-tertiary)]">
          No open findings to decompose.
        </p>
      ) : (
        <>
          <div className="space-y-2.5">
            {rows.slice(0, 10).map((row) => {
              const maxRisk = rows[0]?.riskScore || 1
              const widthPct = Math.max(4, Math.round((row.riskScore / maxRisk) * 100))
              const canFilter = dimensionHasFilter(dimension)
              const href = canFilter ? riskRowHref(dimension, row.label) : undefined
              const label = dimension === "scanner" ? scannerLabel(row.label) : rowLabel(row.label)

              const inner = (
                <>
                  <div className="flex items-center justify-between gap-3">
                    <span className="min-w-0 truncate text-sm font-medium text-[var(--color-text-primary)]">
                      {label}
                    </span>
                    <span className="flex shrink-0 items-center gap-3 text-xs tabular-nums">
                      <span className={`font-semibold ${riskTone(row.riskScore)}`}>
                        {row.riskScore}
                      </span>
                      <span className="text-[var(--color-text-secondary)]">
                        {row.count.toLocaleString()} finding{row.count !== 1 ? "s" : ""}
                      </span>
                      <span className="text-[var(--color-text-tertiary)]">
                        {row.percentage}%
                      </span>
                    </span>
                  </div>
                  <div
                    className="mt-1.5 h-1.5 w-full overflow-hidden rounded-full bg-[var(--color-surface-muted)]"
                    aria-hidden="true"
                  >
                    <div
                      className={`h-full rounded-full ${barTone(row.riskScore)}`}
                      style={{ width: `${widthPct}%` }}
                    />
                  </div>
                </>
              )

              if (!href) {
                return (
                  <div key={row.label || "__unknown"} className="py-1">
                    {inner}
                  </div>
                )
              }
              return (
                <Link
                  key={row.label || "__unknown"}
                  href={href}
                  aria-label={`View ${row.count} findings for ${label} in findings`}
                  className="block rounded-md py-1 transition-colors hover:bg-[var(--color-surface-raised)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)]"
                >
                  {inner}
                </Link>
              )
            })}
          </div>

          <p className="text-2xs text-[var(--color-text-tertiary)]">
            Org total risk score{" "}
            <span className="font-semibold tabular-nums text-[var(--color-text-secondary)]">
              {orgTotal.toLocaleString()}
            </span>
            . Percentages are share of total risk; bars are scaled to the top contributor.
          </p>
        </>
      )}
    </Card>
  )
}

/** Build a Findings deep-link for a risk-contribution row, where the dimension
 *  has a working filter. Labels carry the raw tool/severity/repo value.
 *  state=open aligns the linked view with what the risk score counts. */
function riskRowHref(dim: "scanner" | "repo" | "severity", label: string): string | undefined {
  if (dim === "scanner") return findingsHref({ scanner: label, state: "open" })
  if (dim === "repo") return findingsHref({ repo: label, state: "open" })
  if (dim === "severity") {
    const sev = label.toLowerCase()
    return SEV_ORDER.includes(sev as SevKey)
      ? findingsHref({ severity: sev, state: "open" })
      : undefined
  }
  return undefined
}

function rowLabel(label: string): string {
  if (label === "") return "Unknown"
  if (SEV_ORDER.includes(label.toLowerCase() as SevKey)) {
    return SEV_LABELS[label.toLowerCase() as SevKey]
  }
  return label.charAt(0).toUpperCase() + label.slice(1)
}

/** Bar fill tone for a risk score (uses the bare token — bars, not text). */
function barTone(score: number): string {
  if (score >= 20) return SEV_BAR.critical
  if (score >= 10) return SEV_BAR.high
  if (score >= 3) return SEV_BAR.medium
  if (score > 0) return SEV_BAR.low
  return "bg-[var(--color-text-tertiary)]"
}

// ── Card 2: Scanner breakdown ───────────────────────────────────────────────

function ScannerBreakdownCard({ rows }: { rows: ScannerBreakdownItem[] | null }) {
  return (
    <Card padding="md" className="space-y-4">
      <div>
        <h2 className="text-base font-semibold text-[var(--color-text-primary)]">
          Scanner breakdown
        </h2>
        <p className="text-2xs text-[var(--color-text-secondary)]">
          Open findings and SLA breaches per scanner. Sorted by risk score.
        </p>
      </div>

      {rows == null ? (
        <div className="space-y-2">
          {[0, 1, 2].map((i) => (
            <div
              key={i}
              className="h-10 w-full animate-pulse rounded bg-[var(--color-surface-muted)]"
            />
          ))}
        </div>
      ) : rows.length === 0 ? (
        <p className="py-6 text-center text-sm text-[var(--color-text-tertiary)]">
          No open findings from any scanner.
        </p>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full border-collapse text-sm">
            <thead>
              <tr className="border-b border-[var(--color-border)] text-left text-2xs font-semibold uppercase tracking-[0.14em] text-[var(--color-text-tertiary)]">
                <th className="py-2 pr-4 font-semibold">Scanner</th>
                <th className="py-2 pr-4 font-semibold">Open findings</th>
                <th className="py-2 pr-4 font-semibold">Risk</th>
                <th className="py-2 pr-4 text-right font-semibold">SLA breached</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((row) => {
                const visibleSev = SEV_ORDER.filter((s) => row[s] > 0)
                const href = findingsHref({ scanner: row.scanner, state: "open" })
                return (
                  <tr
                    key={row.scanner}
                    className="border-b border-[var(--color-border)] last:border-0"
                  >
                    <td className="py-2.5 pr-4">
                      <Link
                        href={href}
                        aria-label={`View ${row.total} findings from ${scannerLabel(row.scanner)}`}
                        className="font-medium text-[var(--color-text-primary)] transition-colors hover:text-[var(--color-accent)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)] rounded"
                      >
                        {scannerLabel(row.scanner)}
                      </Link>
                    </td>
                    <td className="py-2.5 pr-4">
                      {visibleSev.length === 0 ? (
                        <span className="text-xs italic text-[var(--color-text-tertiary)]">
                          none
                        </span>
                      ) : (
                        <div>
                          <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
                            {visibleSev.map((s) => (
                              <span
                                key={s}
                                className="flex items-center gap-1 text-xs tabular-nums"
                              >
                                <span
                                  className={`h-1.5 w-1.5 rounded-full ${SEV_DOT[s]}`}
                                  aria-hidden="true"
                                />
                                <span className={`font-semibold ${SEV_TEXT[s]}`}>
                                  {row[s]}
                                </span>
                                <span className="text-[var(--color-text-secondary)]">
                                  {s}
                                </span>
                              </span>
                            ))}
                            <span className="text-xs tabular-nums text-[var(--color-text-tertiary)]">
                              · {row.total.toLocaleString()} total
                            </span>
                          </div>
                          {/* Stacked severity proportion bar */}
                          {(() => {
                            const knownTotal = visibleSev.reduce((s, k) => s + row[k], 0)
                            if (knownTotal === 0) return null
                            return (
                              <div
                                className="mt-1.5 flex h-1 w-full min-w-[80px] overflow-hidden rounded-full"
                                role="img"
                                aria-label={`Severity composition: ${visibleSev.map(s => `${row[s]} ${s}`).join(", ")}`}
                              >
                                {SEV_ORDER.filter((s) => row[s] > 0).map((s) => (
                                  <div
                                    key={s}
                                    className={SEV_BAR[s]}
                                    style={{ width: `${(row[s] / knownTotal) * 100}%` }}
                                  />
                                ))}
                              </div>
                            )
                          })()}
                        </div>
                      )}
                    </td>
                    <td className="py-2.5 pr-4">
                      <span
                        className={`font-semibold tabular-nums ${riskTone(row.riskScore)}`}
                      >
                        {row.riskScore}
                      </span>
                    </td>
                    <td className="py-2.5 pr-4 text-right">
                      {row.slaBreached > 0 ? (
                        <span className="font-semibold tabular-nums text-[var(--color-severity-high-text)]">
                          {row.slaBreached.toLocaleString()}
                        </span>
                      ) : (
                        <span className="text-xs tabular-nums text-[var(--color-text-tertiary)]">
                          0
                        </span>
                      )}
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      )}
    </Card>
  )
}

// ── Card 3: Exploitability ──────────────────────────────────────────────────

function ExploitabilityCard({ data }: { data: ExploitabilitySummary | null }) {
  const kevCount = data?.kevCount ?? 0
  const highEpssCount = data?.highEpssCount ?? 0
  const top = data?.epssTop ?? []

  return (
    <Card padding="md" className="space-y-4">
      <div>
        <h2 className="text-base font-semibold text-[var(--color-text-primary)]">
          Exploitability
        </h2>
        <p className="text-2xs text-[var(--color-text-secondary)]">
          Known exploited vulnerabilities and highest-EPSS findings in your scope.
        </p>
      </div>

      <div className="grid grid-cols-2 gap-3">
        <Link
          href={findingsHref({ kev: true, state: "open" })}
          aria-label={`View ${kevCount} KEV-exposed findings`}
          className="flex flex-col rounded-xl border border-[var(--color-border)] bg-[var(--color-surface-raised)] px-5 py-3 text-left transition-colors hover:border-[var(--color-accent)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)]"
        >
          <p className="text-[11px] font-semibold uppercase tracking-[0.22em] text-[var(--color-text-secondary)]">
            KEV-exposed
          </p>
          <p className="mt-2 text-2xl font-semibold leading-none tabular-nums text-[var(--color-severity-critical-text)]">
            {data == null ? "—" : kevCount.toLocaleString()}
          </p>
          <p className="mt-2 text-sm text-[var(--color-text-secondary)]">
            {data == null
              ? "Loading"
              : kevCount > 0
                ? "In known exploited catalog"
                : "None in catalog"}
          </p>
        </Link>

        {data == null ? (
          <div className="flex flex-col rounded-xl border border-[var(--color-border)] bg-[var(--color-surface-raised)] px-5 py-3 text-left">
            <p className="text-[11px] font-semibold uppercase tracking-[0.22em] text-[var(--color-text-secondary)]">
              High EPSS
            </p>
            <p className="mt-2 text-2xl font-semibold leading-none tabular-nums text-[var(--color-severity-high-text)]">
              —
            </p>
            <p className="mt-2 text-sm text-[var(--color-text-secondary)]">Loading</p>
          </div>
        ) : (
          <Link
            href={findingsHref({ epssMin: 0.9, state: "open" })}
            aria-label={`View ${highEpssCount} high-EPSS findings`}
            className="flex flex-col rounded-xl border border-[var(--color-border)] bg-[var(--color-surface-raised)] px-5 py-3 text-left transition-colors hover:border-[var(--color-accent)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)]"
          >
            <p className="text-[11px] font-semibold uppercase tracking-[0.22em] text-[var(--color-text-secondary)]">
              High EPSS
            </p>
            <p className="mt-2 text-2xl font-semibold leading-none tabular-nums text-[var(--color-severity-high-text)]">
              {highEpssCount.toLocaleString()}
            </p>
            <p className="mt-2 text-sm text-[var(--color-text-secondary)]">
              {highEpssCount > 0 ? "≥ 90th percentile" : "None above threshold"}
            </p>
          </Link>
        )}
      </div>

      {top.length === 0 ? (
        <p className="py-4 text-center text-sm text-[var(--color-text-tertiary)]">
          {data == null ? "Loading top findings…" : "No EPSS-scored findings in scope."}
        </p>
      ) : (
        <div className="space-y-1.5">
          <p className="text-2xs font-semibold uppercase tracking-[0.14em] text-[var(--color-text-tertiary)]">
            Top EPSS findings
          </p>
          {top.map((f) => {
            const sev = severityKey(f.severity)
            // findingId is numeric; FindingsBoardView parses ?finding= as Number()
            // and opens the detail drawer. identityKey is a string → NaN → no-op.
            const href = f.findingId ? findingsHref({ finding: String(f.findingId) }) : undefined
            const inner = (
              <div>
                <div className="flex items-center justify-between gap-3">
                  <div className="flex min-w-0 items-center gap-2">
                    {sev && (
                      <span
                        className={`h-1.5 w-1.5 shrink-0 rounded-full ${SEV_DOT[sev]}`}
                        aria-hidden="true"
                      />
                    )}
                    <span className="min-w-0 truncate text-sm text-[var(--color-text-primary)]">
                      {f.cve || "No CVE"}
                    </span>
                    {sev && (
                      <span
                        className={`shrink-0 text-2xs font-semibold ${SEV_TEXT[sev]}`}
                      >
                        {SEV_LABELS[sev]}
                      </span>
                    )}
                  </div>
                  <span className="flex shrink-0 items-center gap-2 text-xs tabular-nums text-[var(--color-text-secondary)]">
                    <span className="max-w-[12rem] truncate">{f.repo || "—"}</span>
                    <span className="text-[var(--color-text-tertiary)]">·</span>
                    <span className="font-medium">
                      {(f.epssPercentile * 100).toFixed(1)}%
                    </span>
                  </span>
                </div>
                {/* EPSS percentile bar — shows relative exploitability within the top list */}
                <div
                  className="mt-1 h-0.5 w-full overflow-hidden rounded-full bg-[var(--color-surface-muted)]"
                  aria-hidden="true"
                >
                  <div
                    className="h-full rounded-full bg-[var(--color-severity-high)]"
                    style={{ width: `${(f.epssPercentile * 100).toFixed(1)}%` }}
                  />
                </div>
              </div>
            )

            if (!href) {
              return (
                <div
                  key={f.findingId}
                  className="rounded-md px-2 py-1.5"
                >
                  {inner}
                </div>
              )
            }
            return (
              <Link
                key={f.findingId}
                href={href}
                aria-label={`View finding ${f.cve || f.identityKey} in ${f.repo}`}
                className="block rounded-md px-2 py-1.5 transition-colors hover:bg-[var(--color-surface-raised)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)]"
              >
                {inner}
              </Link>
            )
          })}
        </div>
      )}
    </Card>
  )
}

// ── Card 4: SLA posture ─────────────────────────────────────────────────────

function SlaPostureCard({ data }: { data: SlaPostureSummary | null }) {
  const breachStats: { key: SevKey; label: string; count: number }[] = data
    ? [
        { key: "critical", label: "Critical", count: data.criticalBreached },
        { key: "high", label: "High", count: data.highBreached },
        { key: "medium", label: "Medium", count: data.mediumBreached },
        { key: "low", label: "Low", count: data.lowBreached },
      ]
    : []

  const byScanner = data?.byScanner ?? []

  return (
    <Card padding="md" className="space-y-4">
      <div>
        <h2 className="text-base font-semibold text-[var(--color-text-primary)]">
          SLA posture
        </h2>
        <p className="text-2xs text-[var(--color-text-secondary)]">
          Findings past their SLA deadline. Shown by scanner to show where breaches concentrate.
        </p>
      </div>

      {data == null ? (
        <div className="grid grid-cols-4 gap-3">
          {[0, 1, 2, 3].map((i) => (
            <div
              key={i}
              className="h-16 w-full animate-pulse rounded-lg bg-[var(--color-surface-muted)]"
            />
          ))}
        </div>
      ) : data.totalBreached === 0 ? (
        <p className="py-6 text-center text-sm text-[var(--color-text-tertiary)]">
          No SLA breaches. All findings are within their deadline.
        </p>
      ) : (
        <>
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
            {breachStats.map((s) => {
              const inner = (
                <>
                  <div className="flex items-center gap-1.5">
                    <span
                      className={`h-1.5 w-1.5 rounded-full ${SEV_DOT[s.key]}`}
                      aria-hidden="true"
                    />
                    <span className="text-2xs font-semibold uppercase tracking-[0.14em] text-[var(--color-text-tertiary)]">
                      {s.label}
                    </span>
                  </div>
                  <span
                    className={`mt-1.5 text-xl font-semibold leading-none tabular-nums ${s.count > 0 ? SEV_TEXT[s.key] : "text-[var(--color-text-tertiary)]"}`}
                  >
                    {s.count.toLocaleString()}
                  </span>
                </>
              )
              if (s.count === 0) {
                return (
                  <div
                    key={s.key}
                    className="flex flex-col rounded-lg border border-[var(--color-border)] bg-[var(--color-surface-raised)] px-4 py-3"
                  >
                    {inner}
                  </div>
                )
              }
              return (
                <Link
                  key={s.key}
                  href={findingsHref({ severity: s.key, state: "open" })}
                  aria-label={`View ${s.count} open ${s.label} findings`}
                  className="flex flex-col rounded-lg border border-[var(--color-border)] bg-[var(--color-surface-raised)] px-4 py-3 transition-colors hover:border-[var(--color-accent)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)]"
                >
                  {inner}
                </Link>
              )
            })}
          </div>

          {data.maxBreachAgeDays > 0 && (
            <p className="text-xs text-[var(--color-text-secondary)]">
              Oldest breach{" "}
              <strong className="font-semibold tabular-nums text-[var(--color-severity-critical-text)]">
                {data.maxBreachAgeDays}d
              </strong>{" "}
              past deadline.
            </p>
          )}

          {byScanner.length > 0 && (() => {
            const maxBreach = Math.max(...byScanner.map((s) => s.breached), 1)
            return (
              <div className="space-y-1.5">
                <p className="text-2xs font-semibold uppercase tracking-[0.14em] text-[var(--color-text-tertiary)]">
                  Breaches by scanner
                </p>
                <div className="space-y-1">
                  {byScanner.map((s) => (
                    <div key={s.scanner} className="rounded-md px-2 py-1.5">
                      <div className="flex items-center justify-between gap-3">
                        <span className="text-sm text-[var(--color-text-primary)]">
                          {scannerLabel(s.scanner)}
                        </span>
                        <span className="text-xs font-semibold tabular-nums text-[var(--color-severity-high-text)]">
                          {s.breached.toLocaleString()}
                        </span>
                      </div>
                      <div
                        className="mt-1 h-1 w-full overflow-hidden rounded-full bg-[var(--color-surface-muted)]"
                        aria-hidden="true"
                      >
                        <div
                          className="h-full rounded-full bg-[var(--color-severity-high)]"
                          style={{ width: `${Math.round((s.breached / maxBreach) * 100)}%` }}
                        />
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )
          })()}
        </>
      )}
    </Card>
  )
}

/** Map a backend severity string to the canonical SevKey, or null if unknown. */
function severityKey(sev: string): SevKey | null {
  const lower = sev.toLowerCase()
  if (SEV_ORDER.includes(lower as SevKey)) return lower as SevKey
  return null
}
