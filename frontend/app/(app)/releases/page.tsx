import { Suspense } from "react"
import { ReleasesPageClient } from "./ReleasesPageClient"

export const metadata = { title: "Releases" }

export default function ReleasesPage() {
  return (
    <Suspense fallback={null}>
      <ReleasesPageClient />
    </Suspense>
  )
}
