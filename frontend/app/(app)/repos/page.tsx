import { Suspense } from "react"
import { ReposPageClient } from "./ReposPageClient"

export const metadata = { title: "Repositories" }

export default function ReposPage() {
  return (
    <Suspense fallback={null}>
      <ReposPageClient />
    </Suspense>
  )
}
