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
import { getSlaBreachSummary, type SlaBreachSummary } from "@/lib/client/sla-api"

import { PostureSummaryTab, type PostureRange } from "./PostureSummaryTab"
import { PostureGhostPreview } from "./PostureGhostPreview"
import { EmptyOverviewBanner, GhostPreviewWrapper } from "@/components/shared/EmptyOverviewBanner"
import { listSourceConnections } from "@/lib/client/source-connections-api"
import { Button } from "@/components/ui/Button"
import { Card } from "@/components/ui/Card"
import { Skeleton } from "@/components/ui/Skeleton"

export function PosturePageContent() {
  const [snap, setSnap] = useState<PostureSnapshotResponse | null>(null)
  const [trend, setTrend] = useState<PostureTrendResponse | null>(null)
  const [state, setState] = useState<"loading" | "ok" | "error">("loading")
  const [rangeDays, setRangeDays] = useState<PostureRange>(90)

  const [hasSourceConnections, setHasSourceConnections] = useState<boolean | null>(null)
  const [slaSummary, setSlaSummary] = useState<SlaBreachSummary | null>(null)
  const [teams, setTeams] = useState<TeamPostureItem[] | null>(null)
  const [frameworks, setFrameworks] = useState<ComplianceFramework[] | null>(null)
  const [complianceSummaries, setComplianceSummaries] = useState<
    Record<string, ControlSummaryItem[]>
  >({})

  // Snapshot loads once. The trend reloads whenever the time range changes; the
  // previous series stays visible during the refetch so the page doesn't flash.
  useEffect(() => {
    getPostureSnapshot()
      .then((s) => {
        setSnap(s)
        setState("ok")
      })
      .catch(() => setState("error"))
  }, [])

  useEffect(() => {
    let active = true
    getPostureTrend(rangeDays)
      .then((t) => {
        if (active) setTrend(t)
      })
      .catch(() => {
        if (active) setState("error")
      })
    return () => {
      active = false
    }
  }, [rangeDays])

  useEffect(() => {
    listSourceConnections()
      .then((result) => {
        setHasSourceConnections(result.ok ? result.data.connections.length > 0 : false)
      })
      .catch(() => setHasSourceConnections(false))
  }, [])

  useEffect(() => {
    getSlaBreachSummary()
      .then(setSlaSummary)
      .catch(() => setSlaSummary(null))
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

  if (state !== "error" && (!snap || !trend)) {
    return (
      <div className="px-6 py-5 space-y-5">
        <Skeleton className="h-48 rounded-2xl" />
        <Skeleton className="h-24 rounded-2xl" />
        <Skeleton className="h-56 rounded-2xl" />
      </div>
    )
  }

  if (state === "error") {
    return (
      <div className="px-6 py-5">
        <Card padding="none" className="rounded-md px-6 py-12 text-center">
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
    <PostureSummaryTab
      snap={snap}
      trend={trend}
      teams={teams}
      frameworks={frameworks}
      complianceSummaries={complianceSummaries}
      slaSummary={slaSummary}
      rangeDays={rangeDays}
      onRangeChange={setRangeDays}
    />
  )
}
