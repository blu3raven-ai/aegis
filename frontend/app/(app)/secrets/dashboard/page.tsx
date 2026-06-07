"use client"

import { Suspense, useEffect } from "react"
import { useRouter, useSearchParams } from "next/navigation"

function Redirect() {
  const router = useRouter()
  const params = useSearchParams()

  useEffect(() => {
    if (params.get("tab") === "settings") {
      router.replace("/settings/secrets")
    } else {
      router.replace("/findings?scanner=secrets")
    }
  }, [params, router])

  return null
}

export default function SecretsDashboardRedirect() {
  return (
    <Suspense fallback={null}>
      <Redirect />
    </Suspense>
  )
}
