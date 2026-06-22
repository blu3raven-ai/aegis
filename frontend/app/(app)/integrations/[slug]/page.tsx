import { IntegrationDetailPageContent } from "./IntegrationDetailPageContent";

// Returns a stub so the static export build succeeds.
export function generateStaticParams(): { slug: string }[] {
  return [{ slug: "_" }];
}

export default function IntegrationDetailPage({ params }: { params: Promise<{ slug: string }> }) {
  return <IntegrationDetailPageContent params={params} />;
}
