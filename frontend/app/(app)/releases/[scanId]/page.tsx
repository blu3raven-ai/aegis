import { Suspense } from "react"
import { ReleaseDetailPageContent } from "./ReleaseDetailPageContent"

// Returns a stub so the static export build succeeds.
// FastAPI SPA fallback serves this shell for any actual scan ID.
export function generateStaticParams(): { scanId: string }[] {
  return [{ scanId: "_" }]
}

export default function ReleaseDetailPage(_props: { params: Promise<{ scanId: string }> }) {
  return (
    <Suspense fallback={null}>
      <ReleaseDetailPageContent />
    </Suspense>
  )
}
