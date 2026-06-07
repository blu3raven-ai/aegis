"use client"

import { useEffect, useState } from "react"

import {
  getPostureSnapshot,
  getPostureTrend,
  getPostureByTeam,
  type PostureSnapshotResponse,
  type PostureTrendResponse,
  type TeamPostureItem,
} from "@/lib/client/posture-api"
import {
  listFrameworks,
  getFrameworkSummary,
  type ComplianceFramework,
  type ControlSummaryItem,
} from "@/lib/client/compliance-api"

import { PostureSummaryTab } from "./PostureSummaryTab"
import { PostureBreakdownTab } from "./PostureBreakdownTab"
import { PostureGhostPreview } from "./PostureGhostPreview"
import { EmptyOverviewBanner, GhostPreviewWrapper } from "@/components/shared/EmptyOverviewBanner"

const ORG_ID = process.env.NEXT_PUBLIC_ORG_ID ?? "example-org"

const TABS = ["summary", "breakdown"] as const
type PostureTab = (typeof TABS)[number]

const TAB_LABEL: Record<PostureTab, string> = {
  summary: "Summary",
  breakdown: "Breakdown",
}

export function PosturePageContent() {
  const [activeTab, setActiveTab] = useState<PostureTab>("summary")

  const [snap, setSnap] = useState<PostureSnapshotResponse | null>(null)
  const [trend, setTrend] = useState<PostureTrendResponse | null>(null)
  const [state, setState] = useState<"loading" | "ok" | "error">("loading")

  const [teams, setTeams] = useState<TeamPostureItem[] | null>(null)
  const [frameworks, setFrameworks] = useState<ComplianceFramework[] | null>(null)
  const [complianceSummaries, setComplianceSummaries] = useState<
    Record<string, ControlSummaryItem[]>
  >({})

  useEffect(() => {
    void (async () => {
      try {
        const [s, t] = await Promise.all([getPostureSnapshot(), getPostureTrend()])
        setSnap(s)
        setTrend(t)
        setState("ok")
      } catch {
        setState("error")
      }
    })()
  }, [])

  useEffect(() => {
    void (async () => {
      getPostureByTeam()
        .then((res) => setTeams(res.teams))
        .catch(() => setTeams([]))

      let fws: ComplianceFramework[] = []
      try {
        fws = await listFrameworks()
      } catch {
        fws = []
      }
      setFrameworks(fws)

      fws.slice(0, 4).forEach((fw) => {
        getFrameworkSummary(fw.id, ORG_ID)
          .then((controls) =>
            setComplianceSummaries((prev) => ({ ...prev, [fw.id]: controls })),
          )
          .catch(() => {})
      })
    })()
  }, [])

  if (state === "loading") {
    return (
      <div>
        <div className="border-b border-[var(--color-border)] bg-[var(--color-surface)] px-6 flex">
          {TABS.map((tab) => (
            <div
              key={tab}
              className="-mb-px border-b-2 border-transparent px-3 py-2.5 text-sm text-[var(--color-text-tertiary)]"
            >
              {TAB_LABEL[tab]}
            </div>
          ))}
        </div>
        <div className="px-6 py-5 space-y-5">
          <div className="h-48 motion-safe:animate-pulse rounded-2xl bg-[var(--color-surface-raised)]" />
          <div className="h-24 motion-safe:animate-pulse rounded-2xl bg-[var(--color-surface-raised)]" />
          <div className="h-56 motion-safe:animate-pulse rounded-2xl bg-[var(--color-surface-raised)]" />
        </div>
      </div>
    )
  }

  if (state === "error") {
    return (
      <div className="px-6 py-5">
        <div className="rounded-2xl border border-[var(--color-border)] bg-[var(--color-surface)] px-6 py-12 text-center">
          <p className="text-sm font-medium text-[var(--color-text-primary)]">
            Could not load posture data
          </p>
          <p className="mt-1 text-xs text-[var(--color-text-secondary)]">
            The backend may be unavailable. Check that the server is running and try again.
          </p>
          <button
            type="button"
            onClick={() => window.location.reload()}
            className="mt-4 rounded-lg border border-[var(--color-border)] px-4 py-1.5 text-sm text-[var(--color-text-secondary)] hover:bg-[var(--color-surface-raised)] transition-colors"
          >
            Retry
          </button>
        </div>
      </div>
    )
  }

  if (!snap || !trend) return null

  const isEmpty = snap.counts.total === 0 && trend.points.length === 0
  if (isEmpty) {
    return (
      <div className="space-y-5 px-6 py-5">
        <EmptyOverviewBanner
          description="The preview below shows risk score, severity trend, and team breakdown once your first scan completes."
        />
        <GhostPreviewWrapper className="-mx-6 -my-5">
          <PostureGhostPreview />
        </GhostPreviewWrapper>
      </div>
    )
  }

  return (
    <div>
      <nav
        role="tablist"
        aria-label="Posture views"
        className="border-b border-[var(--color-border)] bg-[var(--color-surface)] px-6 flex"
      >
        {TABS.map((tab) => {
          const active = activeTab === tab
          return (
            <button
              key={tab}
              type="button"
              role="tab"
              aria-selected={active}
              onClick={() => setActiveTab(tab)}
              className={`-mb-px border-b-2 px-3 py-2.5 text-sm transition-colors ${
                active
                  ? "border-[var(--color-accent)] font-semibold text-[var(--color-text-primary)]"
                  : "border-transparent text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)]"
              }`}
            >
              {TAB_LABEL[tab]}
            </button>
          )
        })}
      </nav>

      {activeTab === "summary" && (
        <PostureSummaryTab
          snap={snap}
          trend={trend}
          teams={teams}
          frameworks={frameworks}
          complianceSummaries={complianceSummaries}
        />
      )}

      {activeTab === "breakdown" && <PostureBreakdownTab snap={snap} />}
    </div>
  )
}
