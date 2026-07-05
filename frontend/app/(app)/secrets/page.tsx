"use client"

import { FindingsBoardView } from "@/components/shared/findings/FindingsBoardView"
import { FindingsIcon } from "@/lib/shared/ui/page-icons"

export default function SecretsLandingPage() {
  return (
    <FindingsBoardView
      pageTitle="Secret Scanning"
      pageIcon={<FindingsIcon />}
      pageDescription="Exposed secrets detected across your sources."
      initialScannerFilter="secret_scanning"
    />
  )
}
