"use client"

import { Suspense, useEffect, useState } from "react"
import { useRouter, useSearchParams } from "next/navigation"
import { FindingsBoardView } from "@/components/shared/findings/FindingsBoardView"
import { FindingsIcon } from "@/lib/shared/ui/page-icons"

function DependenciesDashboard() {
  const router = useRouter()
  const params = useSearchParams()
  const [routed, setRouted] = useState(false)

  useEffect(() => {
    if (params.get("tab") === "settings") {
      router.replace("/settings/dependencies")
    } else {
      setRouted(true)
    }
  }, [params, router])

  if (!routed) return null

  return (
    <FindingsBoardView
      pageTitle="Dependencies"
      pageIcon={<FindingsIcon />}
      pageDescription="Vulnerabilities from dependency scanning."
      initialScannerFilter="deps"
    />
  )
}

export default function DependenciesDashboardPage() {
  return (
    <Suspense fallback={null}>
      <DependenciesDashboard />
    </Suspense>
  )
}
