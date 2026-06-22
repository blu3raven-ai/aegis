"use client"

import { useEffect, useState } from "react"
import { usePathname } from "next/navigation"

/**
 * `usePathname()` that returns `null` until the component has mounted.
 *
 * The production build uses `output: "export"`, where `usePathname()` is empty
 * during prerender — so nav active state derived from it renders differently on
 * the server than on the client. React does not reconcile `className` mismatches
 * on hydration, so the stale (build-time) active state sticks and the real one
 * never applies. Deferring to post-mount makes the server and first client
 * render agree, then a normal re-render applies the real path.
 *
 * Callers should treat `null` as "nothing active yet" (e.g. `pathname?.startsWith`).
 */
export function useMountedPathname(): string | null {
  const pathname = usePathname()
  const [mounted, setMounted] = useState(false)
  useEffect(() => setMounted(true), [])
  return mounted ? pathname : null
}
