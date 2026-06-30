"use client"

import { Suspense } from "react"
import { useSearchParams } from "next/navigation"

import { FindingsBoardView } from "@/components/shared/findings/FindingsBoardView"
import type { FindingScanner } from "@/lib/client/findings-api"
import { FindingsIcon } from "@/lib/shared/ui/page-icons"

const VALID_SCANNER_PARAMS = new Set<FindingScanner>([
  "dependencies_scanning",
  "code_scanning",
  "container_scanning",
  "secret_scanning",
  "iac_scanning",
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
  return (
    <FindingsBoardView
      pageTitle="Findings"
      pageIcon={<FindingsIcon />}
      initialScannerFilter={initialScanner}
      initialSeverityFilter={params.get("severity") ?? undefined}
      initialRepoFilter={params.get("repo") ?? undefined}
      initialSearch={params.get("q") ?? undefined}
      initialFindingId={params.get("finding") ?? undefined}
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
