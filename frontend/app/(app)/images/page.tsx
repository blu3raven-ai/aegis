import { Suspense } from "react"
import { ImagesPageClient } from "./ImagesPageClient"

export const metadata = { title: "Images" }

export default function ImagesPage() {
  return (
    <Suspense fallback={null}>
      <ImagesPageClient />
    </Suspense>
  )
}
