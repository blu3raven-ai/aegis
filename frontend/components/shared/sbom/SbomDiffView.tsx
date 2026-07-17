"use client"

import { useMemo, useState } from "react"
import type { SbomDiffResponse, SbomComponent, SbomVersionChange, VulnCounts } from "@/lib/client/sbom-diff-api"
import { Card } from "@/components/ui/Card"
import { ComponentVulnBadge } from "@/components/shared/sbom/ComponentVulnBadge"
import { CATEGORY_META, CATEGORY_RANK } from "@/lib/sbom/license-category"
import { breakdown, composition, aggregateCounts, compareSeverity } from "@/lib/sbom/diff-severity"

/** A bump that changes a component's license risk category is a compliance
 * event — red when it gets more restrictive (e.g. MIT → GPL), green when less. */
function LicenseChangeBadge({ change }: { change: SbomVersionChange }) {
  const from = change.from_license_category
  const to = change.to_license_category
  if (!from || !to || from === to) return null
  const worse = CATEGORY_RANK[to] > CATEGORY_RANK[from]
  const cls = worse
    ? "border-[var(--color-severity-critical-border)] bg-[var(--color-severity-critical-subtle)] text-[var(--color-severity-critical-text)]"
    : "border-[var(--color-status-ok-border)] bg-[var(--color-status-ok-subtle)] text-[var(--color-status-ok-text)]"
  const fromLabel = change.from_license || CATEGORY_META[from].label
  const toLabel = change.to_license || CATEGORY_META[to].label
  return (
    <span
      title={`License risk ${worse ? "increased" : "decreased"}: ${CATEGORY_META[from].label} → ${CATEGORY_META[to].label}`}
      className={`inline-flex items-center gap-1 rounded border px-1.5 py-0.5 text-2xs font-semibold ${cls}`}
    >
      <span aria-hidden="true">{worse ? "▴" : "▾"}</span>
      {fromLabel} → {toLabel}
    </span>
  )
}

/** Advisory set-delta badge from the OSV re-match (Signal B). Kept visually and
 * verbally distinct from the findings badge — it reads "advisories", colours
 * green for remediation (resolved/dropped) and red for newly-introduced risk,
 * and never links to /findings (these are version-matched advisories, not
 * triaged findings). */
function AdvisoryBadge({
  counts,
  tone,
  label,
}: {
  counts: VulnCounts | undefined
  tone: "good" | "bad" | "neutral"
  label: string
}) {
  if (!counts || counts.total === 0) return null
  const cls =
    tone === "good"
      ? "border-[var(--color-status-ok-border)] bg-[var(--color-status-ok-subtle)] text-[var(--color-status-ok-text)]"
      : tone === "bad"
        ? "border-[var(--color-severity-critical-border)] bg-[var(--color-severity-critical-subtle)] text-[var(--color-severity-critical-text)]"
        : "border-[var(--color-border)] bg-[var(--color-surface-raised)] text-[var(--color-text-secondary)]"
  const glyph = tone === "good" ? "▾" : tone === "bad" ? "▴" : "•"
  return (
    <span
      title={`${label}: ${breakdown(counts)} (OSV advisories)`}
      className={`inline-flex items-center gap-1 rounded border px-1.5 py-0.5 text-2xs font-semibold tabular-nums ${cls}`}
    >
      <span aria-hidden="true">{glyph}</span>
      {label} {composition(counts)}
    </span>
  )
}

function ChevronIcon({ expanded }: { expanded: boolean }) {
  return (
    <svg
      className={`h-4 w-4 shrink-0 transition-transform ${expanded ? "rotate-90" : ""}`}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={2}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      <path d="M9 18l6-6-6-6" />
    </svg>
  )
}

function SectionHeader({
  label,
  count,
  color,
  expanded,
  onToggle,
}: {
  label: string
  count: number
  color: string
  expanded: boolean
  onToggle: () => void
}) {
  return (
    <button
      type="button"
      onClick={onToggle}
      aria-expanded={expanded}
      className="flex w-full items-center gap-2 rounded-md px-2 py-1.5 text-left transition-colors hover:bg-[var(--color-surface-raised)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)]"
    >
      <ChevronIcon expanded={expanded} />
      <span className="text-xs font-semibold text-[var(--color-text-primary)]">{label}</span>
      <span
        className={`ml-1 rounded-full px-2 py-px font-mono text-2xs font-semibold ${color}`}
      >
        {count}
      </span>
    </button>
  )
}

function ComponentRow({ component, kind }: { component: SbomComponent; kind: "added" | "removed" }) {
  return (
    <li className="flex flex-wrap items-baseline gap-x-2 gap-y-1 py-1 pl-4 text-xs">
      <span className="h-1.5 w-1.5 shrink-0 translate-y-[2px] rounded-full bg-[var(--color-text-tertiary)]" />
      <span className="font-[family-name:var(--font-jetbrains-mono)] text-[var(--color-text-primary)]">
        {component.name}
      </span>
      {component.version && (
        <span className="text-[var(--color-text-tertiary)]">@{component.version}</span>
      )}
      {/* Added: advisories this version introduced (red). Removed: advisories the
          removal dropped (green remediation). */}
      <AdvisoryBadge
        counts={component.known_vulns}
        tone={kind === "removed" ? "good" : "bad"}
        label={kind === "removed" ? "dropped" : "introduced"}
      />
      {/* Current open findings on the to-side asset — only meaningful for added. */}
      {kind === "added" && component.current_findings && component.current_findings.total > 0 && (
        <ComponentVulnBadge vulns={component.current_findings} packageName={component.name} />
      )}
    </li>
  )
}

function VersionChangeRow({ change }: { change: SbomVersionChange }) {
  return (
    <li className="flex flex-wrap items-baseline gap-x-2 gap-y-1 py-1 pl-4 text-xs">
      <span className="h-1.5 w-1.5 shrink-0 translate-y-[2px] rounded-full bg-[var(--color-text-tertiary)]" />
      <span className="font-[family-name:var(--font-jetbrains-mono)] text-[var(--color-text-primary)]">
        {change.name}
      </span>
      <span className="text-[var(--color-text-tertiary)]">
        {change.from_version ?? "?"}
        {" → "}
        {change.to_version ?? "?"}
      </span>
      <AdvisoryBadge counts={change.resolved} tone="good" label="resolved" />
      <AdvisoryBadge counts={change.introduced} tone="bad" label="introduced" />
      <AdvisoryBadge counts={change.still_vulnerable} tone="neutral" label="still vuln" />
      <LicenseChangeBadge change={change} />
      {change.current_findings && change.current_findings.total > 0 && (
        <ComponentVulnBadge vulns={change.current_findings} packageName={change.name} />
      )}
    </li>
  )
}

function EmptyCategory({ message }: { message: string }) {
  return (
    <p className="py-2 pl-4 text-xs text-[var(--color-text-tertiary)]">{message}</p>
  )
}

/** Footer row shown when a category's list was capped server-side, so the
 *  rendered rows are a subset of the true count. */
function TruncatedRow({ shown, total }: { shown: number; total: number }) {
  if (shown >= total) return null
  return (
    <li className="py-2 pl-4 text-2xs text-[var(--color-text-tertiary)]">
      Showing the first {shown.toLocaleString()} of {total.toLocaleString()} — this diff is too large to
      list in full.
    </li>
  )
}

export function SbomDiffView({ diff }: { diff: SbomDiffResponse }) {
  // Default each section open only when its true count (not the possibly
  // server-capped list length) is non-zero, so empty sections collapse and
  // don't render a redundant "No packages …" filler row.
  const [addedOpen, setAddedOpen] = useState(diff.added_count > 0)
  const [removedOpen, setRemovedOpen] = useState(diff.removed_count > 0)
  const [bumpsOpen, setBumpsOpen] = useState(diff.version_changed_count > 0)

  // True totals (the node lists may be capped on a very large container diff).
  const totalChanges =
    diff.added_count + diff.removed_count + diff.version_changed_count

  // Float rows carrying the worst vuln signal to the top of each section (a
  // single critical outranks any number of lows), then by name.
  const added = useMemo(
    () =>
      [...diff.added].sort(
        (a, b) =>
          compareSeverity(a.known_vulns, b.known_vulns) || a.name.localeCompare(b.name),
      ),
    [diff.added],
  )
  const removed = useMemo(
    () =>
      [...diff.removed].sort(
        (a, b) =>
          compareSeverity(a.known_vulns, b.known_vulns) || a.name.localeCompare(b.name),
      ),
    [diff.removed],
  )
  const versionChanged = useMemo(
    () =>
      [...diff.version_changed].sort(
        (a, b) =>
          compareSeverity(
            aggregateCounts([a.resolved, a.introduced]),
            aggregateCounts([b.resolved, b.introduced]),
          ) || a.name.localeCompare(b.name),
      ),
    [diff.version_changed],
  )

  // Remediation = advisories cleared by dropping a package or bumping past a fix.
  const resolvedAgg = aggregateCounts([
    ...diff.version_changed.map((v) => v.resolved),
    ...diff.removed.map((c) => c.known_vulns),
  ])
  const introducedAgg = aggregateCounts([
    ...diff.added.map((c) => c.known_vulns),
    ...diff.version_changed.map((v) => v.introduced),
  ])

  // Signal A: open triaged findings already landing on the packages this diff
  // adds or bumps into. Distinct from the advisory delta (Signal B) above —
  // these are real findings, not version-matched advisories.
  const introducedFindings = aggregateCounts([
    ...diff.added.map((c) => c.current_findings),
    ...diff.version_changed.map((v) => v.current_findings),
  ])

  return (
    <Card padding="none" className="flex flex-col gap-0 divide-y divide-[var(--color-border)] rounded-md overflow-hidden">
      {/* Summary bar */}
      <div className="flex flex-wrap items-center gap-4 px-4 py-3">
        <span className="text-xs text-[var(--color-text-secondary)]">
          <span className="font-semibold tabular-nums text-[var(--color-text-primary)]">
            {totalChanges}
          </span>{" "}
          package change{totalChanges !== 1 ? "s" : ""}
        </span>
        <span className="text-xs text-[var(--color-text-secondary)]">
          <span className="font-semibold tabular-nums text-[var(--color-status-ok-text)]">
            +{diff.added_count}
          </span>{" "}
          added
        </span>
        <span className="text-xs text-[var(--color-text-secondary)]">
          <span className="font-semibold tabular-nums text-[var(--color-severity-critical-text)]">
            -{diff.removed_count}
          </span>{" "}
          removed
        </span>
        <span className="text-xs text-[var(--color-text-secondary)]">
          <span className="font-semibold tabular-nums text-[var(--color-accent)]">
            {diff.version_changed_count}
          </span>{" "}
          version bumps
        </span>
        <span className="text-xs text-[var(--color-text-secondary)]">
          <span className="font-semibold tabular-nums text-[var(--color-text-tertiary)]">
            {diff.unchanged_count}
          </span>{" "}
          unchanged
        </span>

        {/* Right-aligned signal group: open findings (Signal A) + OSV advisory
            delta (Signal B). Wrapped so the group stays right-aligned even when
            one signal is absent. */}
        <div className="ml-auto flex flex-wrap items-center gap-x-4 gap-y-1">
          {/* Signal A — real triaged findings landing on newly-added/bumped packages. */}
          {introducedFindings.total > 0 && (
            <span
              className="flex items-center gap-2 text-xs text-[var(--color-text-secondary)]"
              title={`Open findings on newly-added or bumped packages: ${breakdown(introducedFindings)}`}
            >
              <span className="text-[var(--color-text-tertiary)]">Open findings</span>
              <span className="font-semibold tabular-nums text-[var(--color-severity-critical-text)]">
                <span aria-hidden="true">▴</span> {composition(introducedFindings)}
              </span>{" "}
              introduced
            </span>
          )}

          {/* OSV advisory delta (Signal B) — labelled "advisories", never "findings". */}
          {diff.remediation_signal_available ? (
            (resolvedAgg.total > 0 || introducedAgg.total > 0) && (
              <span className="flex items-center gap-2 text-xs text-[var(--color-text-secondary)]">
                <span className="text-[var(--color-text-tertiary)]">Advisories</span>
                {resolvedAgg.total > 0 && (
                  <span title={`Advisories cleared by removing a package or bumping past a fix: ${breakdown(resolvedAgg)}`}>
                    <span className="font-semibold tabular-nums text-[var(--color-status-ok-text)]">
                      <span aria-hidden="true">▾</span> {composition(resolvedAgg)}
                    </span>{" "}
                    resolved
                  </span>
                )}
                {introducedAgg.total > 0 && (
                  <span title={`Advisories on newly-added or bumped-into versions: ${breakdown(introducedAgg)}`}>
                    <span className="font-semibold tabular-nums text-[var(--color-severity-critical-text)]">
                      <span aria-hidden="true">▴</span> {composition(introducedAgg)}
                    </span>{" "}
                    introduced
                  </span>
                )}
              </span>
            )
          ) : (
            <span className="text-2xs text-[var(--color-text-tertiary)]" title="The OSV advisory mirror is empty or the diff was too large to re-match">
              Remediation signal unavailable
            </span>
          )}
        </div>
      </div>

      {/* Change sections — flat top-level Added / Removed / Version bumps */}
      <div className="flex flex-col px-2 py-2">
        {/* Added */}
        <SectionHeader
          label="Added"
          count={diff.added_count}
          color="bg-[var(--color-status-ok)]/10 text-[var(--color-status-ok-text)]"
          expanded={addedOpen}
          onToggle={() => setAddedOpen((v) => !v)}
        />
        {addedOpen && (
          <ul>
            {added.length === 0 ? (
              <EmptyCategory message="No packages added" />
            ) : (
              <>
                {added.map((c) => (
                  <ComponentRow key={`${c.name}@${c.version}`} component={c} kind="added" />
                ))}
                <TruncatedRow shown={added.length} total={diff.added_count} />
              </>
            )}
          </ul>
        )}

        {/* Removed */}
        <SectionHeader
          label="Removed"
          count={diff.removed_count}
          color="bg-[var(--color-severity-critical-subtle)] text-[var(--color-severity-critical-text)]"
          expanded={removedOpen}
          onToggle={() => setRemovedOpen((v) => !v)}
        />
        {removedOpen && (
          <ul>
            {removed.length === 0 ? (
              <EmptyCategory message="No packages removed" />
            ) : (
              <>
                {removed.map((c) => (
                  <ComponentRow key={`${c.name}@${c.version}`} component={c} kind="removed" />
                ))}
                <TruncatedRow shown={removed.length} total={diff.removed_count} />
              </>
            )}
          </ul>
        )}

        {/* Version bumps */}
        <SectionHeader
          label="Version bumps"
          count={diff.version_changed_count}
          color="bg-[var(--color-accent)]/10 text-[var(--color-accent)]"
          expanded={bumpsOpen}
          onToggle={() => setBumpsOpen((v) => !v)}
        />
        {bumpsOpen && (
          <ul>
            {versionChanged.length === 0 ? (
              <EmptyCategory message="No version bumps" />
            ) : (
              <>
                {versionChanged.map((c) => (
                  <VersionChangeRow key={`${c.name}-${c.from_version}-${c.to_version}`} change={c} />
                ))}
                <TruncatedRow shown={versionChanged.length} total={diff.version_changed_count} />
              </>
            )}
          </ul>
        )}
      </div>
    </Card>
  )
}
