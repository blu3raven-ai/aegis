"use client"

import { useEffect, useState } from "react"

import {
  getPostureSnapshot,
  getPostureTrend,
  getPostureByTeam,
  getPostureScannerBreakdown,
  getPostureExploitabilitySummary,
  getPostureSlaPosture,
  type PostureSnapshotResponse,
  type PostureTrendResponse,
  type TeamPostureItem,
  type ScannerBreakdownItem,
  type ExploitabilitySummary,
  type SlaPostureSummary,
} from "@/lib/client/posture-api"
import {
  listFrameworks,
  getFrameworkSummary,
  type ComplianceFramework,
  type ControlSummaryItem,
} from "@/lib/client/compliance-api"
import { getSlaBreachSummary, type SlaBreachSummary } from "@/lib/client/sla-api"

import { PostureSummaryTab, type PostureRange } from "./PostureSummaryTab"
import { PostureTriageTab } from "./PostureTriageTab"
import { PostureUsageTab } from "./PostureUsageTab"
import { PostureGhostPreview } from "./PostureGhostPreview"
import { EmptyOverviewBanner, GhostPreviewWrapper } from "@/components/shared/EmptyOverviewBanner"
import { listSourceConnections } from "@/lib/client/source-connections-api"
import { useHasPermission } from "@/lib/client/use-permission"
import { NavTabs } from "@/components/ui/NavTabs"
import { Button } from "@/components/ui/Button"
import { Card } from "@/components/ui/Card"
import { Skeleton } from "@/components/ui/Skeleton"

type PostureTab = "overview" | "triage" | "usage"

const BASE_TABS = [
  { id: "overview", label: "Overview" },
  { id: "triage", label: "Triage" },
] as const
// Usage reads the LLM ledger, which is manage_settings-gated — the tab only
// appears for callers who can actually load it (see canViewUsage below).
const USAGE_TAB = { id: "usage", label: "Usage" } as const
const VALID_TABS: PostureTab[] = ["overview", "triage", "usage"]

export function PosturePageContent() {
  const [snap, setSnap] = useState<PostureSnapshotResponse | null>(null)
  const [trend, setTrend] = useState<PostureTrendResponse | null>(null)
  const [state, setState] = useState<"loading" | "ok" | "error">("loading")
  const [rangeDays, setRangeDays] = useState<PostureRange>(90)
  // Tab lives in the URL (?tab=triage) so it deep-links and survives remounts —
  // a background refresh must not silently drop the user back to Overview.
  const [tab, setTab] = useState<PostureTab>(() => {
    if (typeof window === "undefined") return "overview"
    const t = new URLSearchParams(window.location.search).get("tab")
    return VALID_TABS.includes(t as PostureTab) ? (t as PostureTab) : "overview"
  })
  const { allowed: canViewUsage } = useHasPermission("manage_settings")
  // Usage is dropped for non-admins; a deep-link to ?tab=usage they can't view
  // falls back to Overview until (and unless) the permission check resolves true.
  const tabs: readonly { id: PostureTab; label: string }[] = canViewUsage
    ? [...BASE_TABS, USAGE_TAB]
    : BASE_TABS
  const effectiveTab: PostureTab = tab === "usage" && !canViewUsage ? "overview" : tab

  const selectTab = (next: PostureTab) => {
    setTab(next)
    if (typeof window === "undefined") return
    const url = new URL(window.location.href)
    if (next === "overview") url.searchParams.delete("tab")
    else url.searchParams.set("tab", next)
    window.history.replaceState(null, "", url.toString())
  }

  const [hasSourceConnections, setHasSourceConnections] = useState<boolean | null>(null)
  const [slaSummary, setSlaSummary] = useState<SlaBreachSummary | null>(null)
  const [teams, setTeams] = useState<TeamPostureItem[] | null>(null)
  const [frameworks, setFrameworks] = useState<ComplianceFramework[] | null>(null)
  const [complianceSummaries, setComplianceSummaries] = useState<
    Record<string, ControlSummaryItem[]>
  >({})

  // Triage datasets — fetched on mount so both the Overview KPI strip and the
  // Triage tab can read from them. Each degrades to a quiet empty state.
  const [scannerBreakdown, setScannerBreakdown] = useState<ScannerBreakdownItem[] | null>(null)
  const [exploitability, setExploitability] = useState<ExploitabilitySummary | null>(null)
  const [slaPosture, setSlaPosture] = useState<SlaPostureSummary | null>(null)

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

  // Triage + overview KPI datasets load on mount. Each resolver is independent
  // and fails closed (empty result / zeros), so a single failure never blanks
  // a whole tab — the affected card just renders its empty state. The
  // dimension-dependent riskContributions resolver is fetched inside the Triage
  // tab itself (it switches on the selected dimension).
  useEffect(() => {
    getPostureScannerBreakdown()
      .then(setScannerBreakdown)
      .catch(() => setScannerBreakdown([]))
    getPostureExploitabilitySummary()
      .then(setExploitability)
      .catch(() => setExploitability(null))
    getPostureSlaPosture()
      .then(setSlaPosture)
      .catch(() => setSlaPosture(null))
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
    <div>
      <NavTabs
        tabs={tabs}
        activeTab={effectiveTab}
        onChange={selectTab}
        ariaLabel="Insights view"
      />
      {effectiveTab === "overview" ? (
        <PostureSummaryTab
          snap={snap}
          trend={trend}
          teams={teams}
          frameworks={frameworks}
          complianceSummaries={complianceSummaries}
          slaSummary={slaSummary}
          rangeDays={rangeDays}
          onRangeChange={setRangeDays}
          onSwitchToTriage={() => selectTab("triage")}
          exploitability={exploitability}
          slaPosture={slaPosture}
        />
      ) : effectiveTab === "triage" ? (
        <PostureTriageTab
          scannerBreakdown={scannerBreakdown}
          exploitability={exploitability}
          slaPosture={slaPosture}
        />
      ) : (
        <PostureUsageTab />
      )}
    </div>
  )
}
