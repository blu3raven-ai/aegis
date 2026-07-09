import { Suspense } from "react"
import { ReposPageClient } from "./ReposPageClient"

export default function ReposPage() {
  return (
    <Suspense fallback={null}>
      <ReposPageClient />
    </Suspense>
  )
}
