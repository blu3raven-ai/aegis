"use client"

import { usePathname } from "next/navigation"
import { sourceIdFromPathname } from "@/lib/shared/source-path"

// `usePathname()` always reflects the live browser URL, so deriving the id from
// it yields the real connection id on both client navigation and direct load —
// unlike `useParams()`, which returns the static-export stub id ("_") on a hard
// load. See sourceIdFromPathname for the why.
export function useSourceId(): string {
  return sourceIdFromPathname(usePathname())
}
