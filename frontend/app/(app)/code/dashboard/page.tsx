"use client"

import { Suspense, useEffect, useState } from "react"
import { useRouter, useSearchParams } from "next/navigation"
import { FindingsBoardView } from "@/components/shared/findings/FindingsBoardView"
import { FindingsIcon } from "@/lib/shared/ui/page-icons"

function CodeDashboard() {
  const router = useRouter()
  const params = useSearchParams()
  const [routed, setRouted] = useState(false)

  useEffect(() => {
    if (params.get("tab") === "settings") {
      router.replace("/settings/code")
    } else {
      setRouted(true)
    }
  }, [params, router])

  if (!routed) return null

  return (
    <FindingsBoardView
      pageTitle="Code Scanning"
      pageIcon={<FindingsIcon />}
      pageDescription="Findings from static code analysis."
      initialScannerFilter="code_scanning"
    />
  )
}

export default function CodeScanningDashboardPage() {
  return (
    <Suspense fallback={null}>
      <CodeDashboard />
    </Suspense>
  )
}
