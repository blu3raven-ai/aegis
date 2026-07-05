import { CiIntegrationPageContent } from "./CiIntegrationPageContent"

export function generateStaticParams(): { id: string }[] {
  return [{ id: "_" }]
}

export default function SourceCiIntegrationPage({ params }: { params: Promise<{ id: string }> }) {
  return <CiIntegrationPageContent params={params} />
}
