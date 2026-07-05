import { CodeRepoScopeConfigPageContent } from "./CodeRepoScopeConfigPageContent"

// Returns a stub so the static export build succeeds.
export function generateStaticParams(): { id: string }[] {
  return [{ id: "_" }]
}

export default function CodeRepoScopeConfigPage({ params }: { params: Promise<{ id: string }> }) {
  return <CodeRepoScopeConfigPageContent params={params} />
}
