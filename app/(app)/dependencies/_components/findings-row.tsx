"use client"

import { useState } from "react"
import type { DependenciesFinding } from "@/lib/shared/dependencies/types"
import { alertAgeDays, alertPatchVersion, cvssChipClass, formatCvssScore } from "@/lib/shared/dependencies/utils"

const SEV_ORDER: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 }

const SEV_DOT: Record<string, string> = {
  critical: "bg-red-400",
  high: "bg-orange-400",
  medium: "bg-amber-400",
  low: "bg-blue-400",
}

const SEV_TEXT: Record<string, string> = {
  critical: "text-red-400",
  high: "text-orange-400",
  medium: "text-amber-400",
  low: "text-blue-400",
}

// ── Aggregated finding type ──────────────────────────────────────────────────

export interface AggregatedDependenciesFinding {
  /** The "worst" finding in the group — used for display and drawer */
  representative: DependenciesFinding
  /** All findings sharing the same advisory + secondary key (manifest variants) */
  findings: DependenciesFinding[]
  /** Unique group key */
  advisoryKey: string
}

/**
 * Aggregate findings by advisory (GHSA ID) + a secondary key.
 * In repository view, secondary key = package name (one row per advisory per package).
 * In package view, secondary key = repository name (one row per advisory per repo).
 * Manifest-level duplicates are merged into the findings array.
 */
export function aggregateFindings(
  findings: DependenciesFinding[],
  secondaryKey: (f: DependenciesFinding) => string,
): AggregatedDependenciesFinding[] {
  const map = new Map<string, DependenciesFinding[]>()
  for (const f of findings) {
    const key = `${f.repository.full_name}::${f.security_advisory.ghsa_id}::${secondaryKey(f)}`
    const arr = map.get(key)
    if (arr) arr.push(f)
    else map.set(key, [f])
  }

  const aggregated: AggregatedDependenciesFinding[] = []
  for (const [advisoryKey, group] of map) {
    group.sort((a, b) =>
      (SEV_ORDER[a.security_advisory.severity] ?? 9) - (SEV_ORDER[b.security_advisory.severity] ?? 9)
      || (b.security_advisory.cvss.score ?? 0) - (a.security_advisory.cvss.score ?? 0)
    )
    aggregated.push({ representative: group[0], findings: group, advisoryKey })
  }

  // Sort by severity weight desc, then CVSS desc
  aggregated.sort((a, b) => {
    const sa = SEV_ORDER[a.representative.security_advisory.severity] ?? 9
    const sb = SEV_ORDER[b.representative.security_advisory.severity] ?? 9
    if (sa !== sb) return sa - sb
    return (b.representative.security_advisory.cvss.score ?? 0) - (a.representative.security_advisory.cvss.score ?? 0)
  })

  return aggregated
}

// ── Row component ────────────────────────────────────────────────────────────

interface Props {
  item: AggregatedDependenciesFinding
  hideColumn?: "repository" | "package"
}

export function DependenciesFindingRow({ item, hideColumn }: Props) {
  const [showManifests, setShowManifests] = useState(false)
  const f = item.representative
  const sev = f.security_advisory.severity
  const cvss = f.security_advisory.cvss.score
  const patch = alertPatchVersion(f)
  const count = item.findings.length
  const age = Math.max(...item.findings.map((x) => Math.floor(alertAgeDays(x))))
  const ghsa = f.security_advisory.ghsa_id
  const cve = f.security_advisory.cve_id

  return (
    <div className="px-4 py-3">
      {/* Line 1: severity dot + name + patch + count + age */}
      <div className="flex items-center gap-2.5">
        <span className={`h-2 w-2 shrink-0 rounded-full ${SEV_DOT[sev] ?? "bg-gray-400"}`} />
        {hideColumn !== "package" && (
          <span className="font-medium text-sm text-[var(--color-text-primary)] whitespace-nowrap">
            {f.dependency.package.name}
          </span>
        )}
        {hideColumn !== "repository" && (
          <span className="font-medium text-sm text-[var(--color-text-primary)] whitespace-nowrap">
            {f.repository.name}
          </span>
        )}
        {patch ? (
          <span className="whitespace-nowrap font-[family-name:var(--font-jetbrains-mono)] text-xs">
            <span className="text-[var(--color-text-secondary)]">→</span>{" "}
            <span className="text-emerald-400">{patch}</span>
          </span>
        ) : (
          <span className="whitespace-nowrap font-[family-name:var(--font-jetbrains-mono)] text-xs text-[var(--color-text-secondary)]">
            No patch
          </span>
        )}
        {count > 1 && (
          <button
            type="button"
            onClick={(e) => {
              e.stopPropagation()
              setShowManifests((v) => !v)
            }}
            className="shrink-0 rounded-md bg-[var(--color-surface-raised)] px-1.5 py-0.5 text-[11px] font-semibold tabular-nums text-[var(--color-text-secondary)] transition-colors hover:text-[var(--color-text-primary)]"
          >
            {count} affected {showManifests ? "▾" : "▸"}
          </button>
        )}
        <span className="ml-auto shrink-0 tabular-nums text-xs text-[var(--color-text-secondary)] whitespace-nowrap">
          {age > 0 ? `${age}d` : "–"}
        </span>
      </div>

      {/* Line 2: severity · CVSS · advisory ID */}
      <div className="mt-1 flex items-center gap-1.5 pl-[18px] text-xs">
        <span className={`font-semibold capitalize ${SEV_TEXT[sev] ?? ""}`}>{sev}</span>
        <span className="text-[var(--color-text-secondary)]">·</span>
        <span className={`tabular-nums font-semibold ${cvssChipClass(cvss)}`}>
          {formatCvssScore(cvss)}
        </span>
        <span className="text-[var(--color-text-secondary)]">·</span>
        <span className="font-[family-name:var(--font-jetbrains-mono)] text-[var(--color-text-secondary)]">
          {cve ?? ghsa}
        </span>
      </div>

      {/* Expandable manifest list */}
      {showManifests && count > 1 && (
        <div className="mt-2 space-y-1 rounded-lg border border-[var(--color-border)] bg-[var(--color-surface-raised)] p-2 ml-[18px]">
          {item.findings.map((finding, i) => (
            <div key={i} className="flex items-center gap-2 text-xs">
              <span className="font-[family-name:var(--font-jetbrains-mono)] text-[var(--color-text-secondary)] truncate" title={finding.dependency.manifest_path}>
                {finding.dependency.manifest_path}
              </span>
              {finding.current_version && (
                <span className="shrink-0 font-[family-name:var(--font-jetbrains-mono)] text-[var(--color-text-secondary)]">
                  @{finding.current_version}
                </span>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
