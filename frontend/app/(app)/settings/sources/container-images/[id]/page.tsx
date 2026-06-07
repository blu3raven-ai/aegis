import { ContainerImageScopeConfigContent } from "./ContainerImageScopeConfigContent"

// Returns a stub so the static export build succeeds.
export function generateStaticParams(): { id: string }[] {
  return [{ id: "_" }]
}

export default function ContainerImageScopeConfigPage({
  params,
}: {
  params: Promise<{ id: string }>
}) {
  return <ContainerImageScopeConfigContent params={params} />
}
