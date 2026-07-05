"use client"

import { use, useEffect } from "react"
import { useRouter } from "next/navigation"

/**
 * Reads the real finding id at runtime (the static export only builds the
 * `_` stub) and redirects to the list with `?finding=<id>` so the drawer opens.
 */
export function FindingRedirectClient({
  params,
}: {
  params: Promise<{ id: string }>
}) {
  const { id } = use(params)
  const router = useRouter()
  useEffect(() => {
    router.replace(
      id && id !== "_" ? `/findings?finding=${encodeURIComponent(id)}` : "/findings",
    )
  }, [id, router])
  return null
}
