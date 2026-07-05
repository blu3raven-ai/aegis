import { SbomRepoPageContent } from "./SbomRepoPageContent"

// Returns a stub so the static export build succeeds.
// FastAPI SPA fallback serves this shell for any actual repo ID.
export function generateStaticParams(): { repoId: string }[] {
  return [{ repoId: "_" }]
}

export default function SbomRepoPage({ params }: { params: Promise<{ repoId: string }> }) {
  return <SbomRepoPageContent params={params} />
}
