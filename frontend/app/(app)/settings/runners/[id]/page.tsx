import { RunnerDetailPageContent } from "./RunnerDetailPageContent"

// Returns a stub so the static export build succeeds.
export function generateStaticParams(): { id: string }[] {
  return [{ id: "_" }]
}

export default function RunnerDetailPage({
  params,
}: {
  params: Promise<{ id: string }>
}) {
  return <RunnerDetailPageContent params={params} />
}
