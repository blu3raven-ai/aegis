"use client";
import { use } from "react";
import { redirect } from "next/navigation";

import { PageHeader } from "@/components/layout/PageHeader";
import { useConnectorCatalog } from "@/lib/client/connectors-api";
import { IntegrationLogoMark } from "../_components/IntegrationLogo";
import { IntegrationSetup } from "../_components/IntegrationSetup";

export default function IntegrationDetailPage({ params }: { params: Promise<{ slug: string }> }) {
  const { slug } = use(params);
  const { catalog, loading } = useConnectorCatalog();
  const integration = catalog.find(i => i.slug === slug);

  if (loading) {
    return <p className="px-6 py-4 text-sm text-[var(--color-text-secondary)]">Loading…</p>;
  }

  if (integration?.href) redirect(integration.href);

  if (!integration) {
    return <p className="px-6 py-4 text-sm text-[var(--color-text-secondary)]">Integration not found.</p>;
  }

  return (
    <>
      <PageHeader
        icon={<IntegrationLogoMark iconSlug={integration.iconSlug} name={integration.name} className="h-5 w-5 text-[var(--color-text-primary)]" />}
        title={integration.name}
        description={integration.description}
      />
      <div className="max-w-3xl px-6 pb-12 pt-6">
        <IntegrationSetup integration={integration} />
      </div>
    </>
  );
}
