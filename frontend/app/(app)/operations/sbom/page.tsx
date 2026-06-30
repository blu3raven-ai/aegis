"use client"

import { useEffect } from "react"
import { useRouter } from "next/navigation"

/**
 * The SBOM explorer moved into the SBOM section (Inventory › SBOM › Components).
 * Keep this path as a redirect so old links resolve. Client-side because the
 * production build is a static export with no server redirects.
 */
export default function OperationsSbomRedirect() {
  const router = useRouter()
  useEffect(() => {
    router.replace("/sbom/components")
  }, [router])
  return null
}
