import { Suspense } from "react"
import { ReleasesPageClient } from "./ReleasesPageClient"

export default function ReleasesPage() {
  return (
    <Suspense fallback={null}>
      <ReleasesPageClient />
    </Suspense>
  )
}
