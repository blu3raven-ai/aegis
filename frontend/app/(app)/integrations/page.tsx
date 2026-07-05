"use client";
import { Suspense, useMemo, useState } from "react";
import { useSearchParams } from "next/navigation";

import { PageHeader } from "@/components/layout/PageHeader";
import { FilterChip } from "@/components/ui/FilterChip";
import { Card } from "@/components/ui/Card";
import { IntegrationsIcon } from "@/lib/shared/ui/page-icons";
import { IntegrationCard } from "./_components/IntegrationCard";
import { IntegrationDrawer } from "./_components/IntegrationDrawer";
import { useConnectorCatalog, type Integration } from "@/lib/client/integrations-catalog-api";

type CategoryFilter = "all" | string;

const CATEGORY_LABELS: Record<string, string> = {
  cicd: "CI/CD",
  notifications: "Notifications",
  ticketing: "Ticketing",
  automation: "Automation",
  runner: "Federated runners",
};

const CATEGORY_ORDER: string[] = ["cicd", "notifications", "ticketing", "automation", "runner"];

function IntegrationsPageContent() {
  const searchParams = useSearchParams();
  const initialCategory = searchParams.get("category") ?? "all";
  const [filter, setFilter] = useState<CategoryFilter>(initialCategory);
  const [selected, setSelected] = useState<Integration | null>(null);

  const { catalog: INTEGRATIONS, loading } = useConnectorCatalog();

  const categoryCounts = useMemo(() => {
    const counts = new Map<string, number>();
    for (const i of INTEGRATIONS) counts.set(i.category, (counts.get(i.category) ?? 0) + 1);
    return counts;
  }, [INTEGRATIONS]);

  const items = INTEGRATIONS.filter(i => filter === "all" || i.category === filter);

  return (
    <>
      <PageHeader
        icon={<IntegrationsIcon />}
        title="Integrations"
        description="Connect Aegis to your CI/CD, notification, and runner surfaces"
        count={INTEGRATIONS.length}
      />
      <div className="px-6 py-5 space-y-5">
        <div className="flex flex-wrap gap-2" role="group" aria-label="Filter by category">
          <FilterChip
            label="All"
            active={filter === "all"}
            count={INTEGRATIONS.length}
            onClick={() => setFilter("all")}
          />
          {CATEGORY_ORDER.map(cat => (
            <FilterChip
              key={cat}
              label={CATEGORY_LABELS[cat]}
              active={filter === cat}
              count={categoryCounts.get(cat) ?? 0}
              onClick={() => setFilter(cat)}
            />
          ))}
        </div>
        {loading ? (
          <Card padding="none" className="rounded-xl border-dashed px-4 py-8 text-center text-sm text-[var(--color-text-secondary)]">
            Loading integrations…
          </Card>
        ) : items.length === 0 ? (
          <Card padding="none" className="rounded-xl border-dashed px-4 py-8 text-center text-sm text-[var(--color-text-secondary)]">
            No integrations in this category yet.
          </Card>
        ) : (
          <div className="grid grid-cols-1 gap-3.5 md:grid-cols-2 lg:grid-cols-3">
            {items.map(i => <IntegrationCard key={i.slug} i={i} onSelect={setSelected} />)}
          </div>
        )}
      </div>
      <IntegrationDrawer integration={selected} onClose={() => setSelected(null)} />
    </>
  );
}

export default function IntegrationsPage() {
  return (
    <Suspense>
      <IntegrationsPageContent />
    </Suspense>
  );
}
