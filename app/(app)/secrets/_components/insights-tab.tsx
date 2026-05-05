"use client"

import { useState } from "react"
import { InsightCard } from "@/components/shared/InsightCard"
import { BacklogHealthChart } from "@/app/(app)/secrets/_components/backlog-health-chart"
import { SecretTypeChart } from "@/app/(app)/secrets/_components/secret-type-chart"
import { BacklogChangeWaterfallChart } from "@/app/(app)/secrets/_components/backlog-change-waterfall-chart"
import { SecretsKpiStrip } from "@/app/(app)/secrets/_components/secrets-kpi-strip"
import { OrgSecretHeatmap } from "@/app/(app)/secrets/_components/org-secret-heatmap"
import { OrgAgeBucketsChart } from "@/app/(app)/secrets/_components/org-age-buckets-chart"
import { RepoRiskScatterChart } from "@/app/(app)/secrets/_components/repo-risk-scatter-chart"
import { TriageFunnelChart } from "@/app/(app)/secrets/_components/triage-funnel-chart"
import type { SecretFinding, SecretsInsightsRepoPriority, SecretsTrendEntry } from "@/lib/shared/secrets/types"

export function InsightsTab({
  triagePriority,
  trend,
  findings,
  availableSources,
  availableOrganizations,
  onSelectRepository,
  onSelectKeyType,
  onSelectCell,
  onSelectAgeBucket,
  onFilterChange,
}: {
  triagePriority: SecretsInsightsRepoPriority[]
  trend: SecretsTrendEntry[]
  findings: SecretFinding[]
  availableSources: string[]
  availableOrganizations: string[]
  onSelectRepository: (repository: string) => void
  onSelectKeyType: (detector: string, status?: string) => void
  onSelectCell: (org: string, detectors: string[]) => void
  onSelectAgeBucket: (bucket: string) => void
  onFilterChange: (filters: { source?: string; organization?: string }) => void
}) {
  const [sourceFilter, setSourceFilter] = useState("")
  const [organizationFilter, setOrganizationFilter] = useState("")

  function handleFilters(patch: { source?: string; organization?: string }) {
    if ("source" in patch) setSourceFilter(patch.source || "")
    if ("organization" in patch) setOrganizationFilter(patch.organization || "")
    onFilterChange({
      source: "source" in patch ? patch.source : sourceFilter || undefined,
      organization: "organization" in patch ? patch.organization : organizationFilter || undefined,
    })
  }

  const filteredFindings = findings.filter((finding) => {
    if (sourceFilter && finding.source.toLowerCase() !== sourceFilter.toLowerCase()) return false
    if (organizationFilter && finding.organization.toLowerCase() !== organizationFilter.toLowerCase()) return false
    return true
  })

  const topConfirmed = [...triagePriority]
    .sort((a, b) => b.confirmedCount - a.confirmedCount)
    .filter((r) => r.confirmedCount > 0)
    .slice(0, 10)

  return (
    <div className="space-y-12">
      {/* Narrative Section 1: Safety Trend */}
      <section className="space-y-6">
        <div className="border-t border-[var(--color-border)] pt-12">
          <h2 className="text-2xl font-bold text-[var(--color-text-primary)]">Safety Trend</h2>
          <p className="mt-1 text-sm text-[var(--color-text-secondary)]">
            Are we reducing open exposure faster than new secrets are being found?
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-3">
          <select
            value={sourceFilter}
            onChange={(event) => handleFilters({ source: event.target.value || undefined, organization: organizationFilter || undefined })}
            className="min-w-44 rounded-xl border border-[var(--color-border)] bg-[var(--color-surface)] px-3 py-2.5 text-sm text-[var(--color-text-primary)]"
          >
            <option value="">All sources</option>
            {availableSources.map((source) => (
              <option key={source} value={source}>{source}</option>
            ))}
          </select>
          <select
            value={organizationFilter}
            onChange={(event) => handleFilters({ source: sourceFilter || undefined, organization: event.target.value || undefined })}
            className="min-w-48 rounded-xl border border-[var(--color-border)] bg-[var(--color-surface)] px-3 py-2.5 text-sm text-[var(--color-text-primary)]"
          >
            <option value="">All organizations</option>
            {availableOrganizations.map((organization) => (
              <option key={organization} value={organization}>{organization}</option>
            ))}
          </select>
        </div>

        <SecretsKpiStrip trend={trend} findings={filteredFindings} />

        <div className="grid gap-5 lg:grid-cols-[minmax(0,1.35fr)_minmax(320px,0.9fr)]">
          <InsightCard
            eyebrow="Backlog Health"
            title="Unresolved exposure"
            description="Total open findings over time. A downward slope indicates progress."
          >
            <BacklogHealthChart trend={trend} />
          </InsightCard>

          <BacklogChangeWaterfallChart trend={trend} />
        </div>
      </section>

      {/* Narrative Section 2: Risk Concentration */}
      <section className="space-y-6">
        <div className="border-t border-[var(--color-border)] pt-12">
          <h2 className="text-2xl font-bold text-[var(--color-text-primary)]">Risk Concentration</h2>
          <p className="mt-1 text-sm text-[var(--color-text-secondary)]">Where is the highest risk hidden in the organization?</p>
        </div>

        <InsightCard eyebrow="By Organization" title="Hotspot heatmap" description="Which org + secret type combinations have the highest unresolved volume?">
          <OrgSecretHeatmap findings={findings} onSelectCell={onSelectCell} />
        </InsightCard>

        <div className="grid gap-6 lg:grid-cols-2">
          <InsightCard eyebrow="By Secret Type" title="Credential categories" description="Cloud and DB secrets carry the widest blast radius.">
            <SecretTypeChart findings={findings} onSelectKeyType={onSelectKeyType} />
          </InsightCard>
          <InsightCard eyebrow="By Age" title="Age distribution" description="Older unresolved secrets are more likely to have been exploited.">
            <OrgAgeBucketsChart findings={findings} onSelectAgeBucket={onSelectAgeBucket} />
          </InsightCard>
        </div>
      </section>

      {/* Narrative Section 3: Action Priorities */}
      <section className="space-y-6">
        <div className="border-t border-[var(--color-border)] pt-12">
          <h2 className="text-2xl font-bold text-[var(--color-text-primary)]">Action Priorities</h2>
          <p className="mt-1 text-sm text-[var(--color-text-secondary)]">Which repositories and teams should be engaged first?</p>
        </div>

        <div className="grid gap-6 lg:grid-cols-2">
          <InsightCard eyebrow="By Repository" title="Risk vs Volume" description="Target repositories in the top-right quadrant (High Risk + High Volume).">
            <RepoRiskScatterChart findings={findings} onSelectRepository={onSelectRepository} />
          </InsightCard>
          <InsightCard eyebrow="Triage Efficiency" title="Monthly triage funnel" description="Are we resolving secrets as fast as they are being detected?">
            <TriageFunnelChart trend={trend} />
          </InsightCard>
        </div>

        <InsightCard eyebrow="By Repository" title="Top 10 repos for triage" description="Ranked by total confirmed unresolved secrets.">
          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-5">
            {topConfirmed.map((repo) => (
              <button
                key={`${repo.organization}/${repo.repository}`}
                type="button"
                onClick={() => onSelectRepository(repo.repository)}
                className="flex items-center justify-between gap-3 rounded-2xl border border-[var(--color-border)] bg-[var(--color-surface-raised)] px-4 py-3 text-left transition-all hover:border-blue-300"
              >
                <span className="min-w-0 truncate text-sm font-medium text-[var(--color-text-primary)]">{repo.repository}</span>
                <span className="shrink-0 rounded-full bg-red-500 px-2 py-0.5 text-xs font-bold text-white">{repo.confirmedCount}</span>
              </button>
            ))}
          </div>
        </InsightCard>
      </section>
    </div>
  )
}
