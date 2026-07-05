"use client"

import { FindingsBoardView } from "@/components/shared/findings/FindingsBoardView"
import { FindingsIcon } from "@/lib/shared/ui/page-icons"

export default function CodeLandingPage() {
  return (
    <FindingsBoardView
      pageTitle="Code Scanning"
      pageIcon={<FindingsIcon />}
      pageDescription="Findings from static code analysis."
      initialScannerFilter="code_scanning"
    />
  )
}
