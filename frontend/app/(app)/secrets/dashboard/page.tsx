"use client"

import { Suspense, useEffect, useState } from "react"
import { useRouter, useSearchParams } from "next/navigation"
import { FindingsBoardView } from "@/components/shared/findings/FindingsBoardView"
import { FindingsIcon } from "@/lib/shared/ui/page-icons"

function SecretsDashboard() {
  const router = useRouter()
  const params = useSearchParams()
  const [routed, setRouted] = useState(false)

  useEffect(() => {
    if (params.get("tab") === "settings") {
      router.replace("/settings/secrets")
    } else {
      setRouted(true)
    }
  }, [params, router])

  if (!routed) return null

  return (
    <FindingsBoardView
      pageTitle="Secret Scanning"
      pageIcon={<FindingsIcon />}
      pageDescription="Exposed secrets detected across your sources."
      initialScannerFilter="secret_scanning"
    />
  )
}

export default function SecretsDashboardPage() {
  return (
    <Suspense fallback={null}>
      <SecretsDashboard />
    </Suspense>
  )
}
