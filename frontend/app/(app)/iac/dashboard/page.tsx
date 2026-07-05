"use client"

import { Suspense, useEffect, useState } from "react"
import { useRouter, useSearchParams } from "next/navigation"
import { FindingsBoardView } from "@/components/shared/findings/FindingsBoardView"
import { FindingsIcon } from "@/lib/shared/ui/page-icons"

function IacDashboard() {
  const router = useRouter()
  const params = useSearchParams()
  const [routed, setRouted] = useState(false)

  useEffect(() => {
    if (params.get("tab") === "settings") {
      router.replace("/settings/iac-security")
    } else {
      setRouted(true)
    }
  }, [params, router])

  if (!routed) return null

  return (
    <FindingsBoardView
      pageTitle="IaC Security"
      pageIcon={<FindingsIcon />}
      pageDescription="Infrastructure-as-Code misconfigurations."
      initialScannerFilter="iac_scanning"
    />
  )
}

export default function IacDashboardPage() {
  return (
    <Suspense fallback={null}>
      <IacDashboard />
    </Suspense>
  )
}
