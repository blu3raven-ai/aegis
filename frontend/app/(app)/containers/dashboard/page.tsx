"use client"

import { Suspense, useEffect, useState } from "react"
import { useRouter, useSearchParams } from "next/navigation"
import { FindingsBoardView } from "@/components/shared/findings/FindingsBoardView"
import { FindingsIcon } from "@/lib/shared/ui/page-icons"

function ContainersDashboard() {
  const router = useRouter()
  const params = useSearchParams()
  const [routed, setRouted] = useState(false)

  useEffect(() => {
    if (params.get("tab") === "settings") {
      router.replace("/settings/containers")
    } else {
      setRouted(true)
    }
  }, [params, router])

  if (!routed) return null

  return (
    <FindingsBoardView
      pageTitle="Container Scanning"
      pageIcon={<FindingsIcon />}
      pageDescription="Vulnerabilities found in container images."
      initialScannerFilter="container_scanning"
    />
  )
}

export default function ContainersDashboardPage() {
  return (
    <Suspense fallback={null}>
      <ContainersDashboard />
    </Suspense>
  )
}
