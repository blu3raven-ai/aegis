import { Suspense } from "react"
import { ImagesPageClient } from "./ImagesPageClient"

export default function ImagesPage() {
  return (
    <Suspense fallback={null}>
      <ImagesPageClient />
    </Suspense>
  )
}
