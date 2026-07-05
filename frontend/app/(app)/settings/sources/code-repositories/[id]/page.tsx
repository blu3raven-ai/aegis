import { CodeRepositoryScopeConfigContent } from "./CodeRepositoryScopeConfigContent"

// Returns a stub so the static export build succeeds.
export function generateStaticParams(): { id: string }[] {
  return [{ id: "_" }]
}

export default function CodeRepositoryScopeConfigPage({
  params,
}: {
  params: Promise<{ id: string }>
}) {
  return <CodeRepositoryScopeConfigContent params={params} />
}
