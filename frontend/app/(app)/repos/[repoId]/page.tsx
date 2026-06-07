import { Suspense } from "react"
import { RepoDetailPageContent } from "./RepoDetailPageContent"

// Returns a stub so the static export build succeeds.
// FastAPI SPA fallback serves this shell for any actual repo ID.
export function generateStaticParams(): { repoId: string }[] {
  return [{ repoId: "_" }]
}

export default function RepoDetailPage(_props: { params: Promise<{ repoId: string }> }) {
  return (
    <Suspense fallback={null}>
      <RepoDetailPageContent />
    </Suspense>
  )
}
