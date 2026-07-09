"use client"

import { Suspense } from "react"
import { useSearchParams } from "next/navigation"

import { FindingsBoardView } from "@/components/shared/findings/FindingsBoardView"
import type { FindingScanner, FindingState } from "@/lib/client/findings-api"
import { FindingsIcon } from "@/lib/shared/ui/page-icons"
import { parseVerdictFilter } from "@/lib/shared/findings/verdicts"

const VALID_SCANNER_PARAMS = new Set<FindingScanner>([
  "dependencies_scanning",
  "code_scanning",
  "container_scanning",
  "secret_scanning",
  "iac_scanning",
  "agent_scanning",
])

const VALID_STATE_PARAMS = new Set<FindingState>([
  "open",
  "closed",
  "dismissed",
  "fixed",
  "deferred",
])

function FindingsBoard() {
  // Deep-link filters (e.g. a posture tile → /findings?severity=critical&repo=…,
  // or a scanner tile → /findings?scanner=code_scanning). Values are
  // validated/scoped inside FindingsBoardView; the backend still enforces
  // permission + asset scope, so these only narrow the result set.
  const params = useSearchParams()
  const scannerParam = params.get("scanner")
  const initialScanner =
    scannerParam && VALID_SCANNER_PARAMS.has(scannerParam as FindingScanner)
      ? (scannerParam as FindingScanner)
      : undefined
  const stateParam = params.get("state")
  const initialState =
    stateParam && VALID_STATE_PARAMS.has(stateParam as FindingState)
      ? [stateParam as FindingState]
      : undefined
  // epss_min is a 0-1 fraction; only apply when the param is actually present
  // and numeric. Note Number(null) === 0, so we must check for the param's
  // presence first — otherwise an absent param would wrongly seed a 0 floor.
  const epssMinRaw = params.get("epss_min")
  const initialEpssMin =
    epssMinRaw != null && epssMinRaw !== "" && Number.isFinite(Number(epssMinRaw))
      ? Number(epssMinRaw)
      : undefined
  return (
    <FindingsBoardView
      pageTitle="Findings"
      pageIcon={<FindingsIcon />}
      initialScannerFilter={initialScanner}
      initialStateFilter={initialState}
      initialSeverityFilter={params.get("severity") ?? undefined}
      initialRepoFilter={params.get("repo") ?? undefined}
      initialKevFilter={params.get("kev") === "true"}
      initialEpssMinFilter={initialEpssMin}
      initialSearch={params.get("q") ?? undefined}
      initialFindingId={params.get("finding") ?? undefined}
      initialCwe={params.get("cwe") ?? undefined}
      initialBands={params.get("bands") ?? undefined}
      initialAssignee={params.get("assignee") ?? undefined}
      initialSort={params.get("sort") ?? undefined}
      initialAge={params.get("age") ?? undefined}
      initialVerdictFilter={parseVerdictFilter(params.get("verdict"))}
      syncUrl
    />
  )
}

export default function FindingsPage() {
  return (
    <Suspense fallback={null}>
      <FindingsBoard />
    </Suspense>
  )
}
