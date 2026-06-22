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
import { listSourceConnections } from "@/lib/client/source-connections-api"
import { NavTabs } from "@/components/ui/NavTabs"
import { Button } from "@/components/ui/Button"
import { Card } from "@/components/ui/Card"
import { Skeleton } from "@/components/ui/Skeleton"

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

  const [hasSourceConnections, setHasSourceConnections] = useState<boolean | null>(null)
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
    listSourceConnections()
      .then((result) => {
        setHasSourceConnections(result.ok ? result.data.connections.length > 0 : false)
      })
      .catch(() => setHasSourceConnections(false))
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
        getFrameworkSummary(fw.id)
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
        <div className="sticky top-[var(--page-header-offset)] z-10 border-b border-[var(--color-border)] bg-[var(--color-surface)] px-6 flex">
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
          <Skeleton className="h-48 rounded-2xl" />
          <Skeleton className="h-24 rounded-2xl" />
          <Skeleton className="h-56 rounded-2xl" />
        </div>
      </div>
    )
  }

  if (state === "error") {
    return (
      <div className="px-6 py-5">
        <Card padding="none" className="rounded-2xl px-6 py-12 text-center">
          <p className="text-sm font-medium text-[var(--color-text-primary)]">
            Could not load posture data
          </p>
          <p className="mt-1 text-xs text-[var(--color-text-secondary)]">
            The backend may be unavailable. Check that the server is running and try again.
          </p>
          <div className="mt-4 inline-flex">
            <Button variant="secondary" size="sm" onClick={() => window.location.reload()}>
              Retry
            </Button>
          </div>
        </Card>
      </div>
    )
  }

  if (!snap || !trend) return null

  const isEmpty = snap.counts.total === 0 && trend.points.length === 0
  if (isEmpty) {
    return (
      <div className="space-y-5 px-6 py-5">
        {hasSourceConnections !== null && (
          <EmptyOverviewBanner
            {...(hasSourceConnections === true
              ? {
                  title: "No posture data yet",
                  description: "Your source is connected. Run a scan to start seeing risk scores and trend data here.",
                  ctaHref: "/sources",
                  ctaLabel: "View sources",
                }
              : {})}
          />
        )}
        <GhostPreviewWrapper className="-mx-6 -my-5">
          <PostureGhostPreview />
        </GhostPreviewWrapper>
      </div>
    )
  }

  return (
    <div>
      <NavTabs
        ariaLabel="Posture views"
        activeTab={activeTab}
        onChange={setActiveTab}
        containerClassName="sticky top-[var(--page-header-offset)] z-10"
        tabs={TABS.map((tab) => ({ id: tab, label: TAB_LABEL[tab] }))}
      />

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
