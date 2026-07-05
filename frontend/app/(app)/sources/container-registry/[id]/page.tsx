import { ContainerRegistryScopeConfigPageContent } from "./ContainerRegistryScopeConfigPageContent"

// Returns a stub so the static export build succeeds.
export function generateStaticParams(): { id: string }[] {
  return [{ id: "_" }]
}

export default function ContainerRegistryScopeConfigPage({ params }: { params: Promise<{ id: string }> }) {
  return <ContainerRegistryScopeConfigPageContent params={params} />
}
