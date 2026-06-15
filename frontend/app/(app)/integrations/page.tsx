"use client";
import { useMemo, useState } from "react";

import { PageHeader } from "@/components/layout/PageHeader";
import { FilterChip } from "@/components/ui/FilterChip";
import { IntegrationsIcon } from "@/lib/shared/ui/page-icons";
import { IntegrationCard } from "./_components/IntegrationCard";
import { IntegrationDrawer } from "./_components/IntegrationDrawer";
import { useConnectorCatalog, type Integration, type ConnectorCategory as IntegrationCategory } from "@/lib/client/connectors-api";

type CategoryFilter = "all" | IntegrationCategory;

const CATEGORY_LABELS: Record<IntegrationCategory, string> = {
  ci: "CI/CD",
  notification: "Notifications",
  runner: "Federated runners",
};

const CATEGORY_ORDER: IntegrationCategory[] = ["ci", "notification", "runner"];

export default function IntegrationsPage() {
  const [filter, setFilter] = useState<CategoryFilter>("all");
  const [selected, setSelected] = useState<Integration | null>(null);

  const { catalog: INTEGRATIONS, loading } = useConnectorCatalog();

  const categoryCounts = useMemo(() => {
    const counts = new Map<IntegrationCategory, number>();
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
          <p className="rounded-xl border border-dashed border-[var(--color-border)] bg-[var(--color-surface)] px-4 py-8 text-center text-sm text-[var(--color-text-secondary)]">
            Loading integrations…
          </p>
        ) : items.length === 0 ? (
          <p className="rounded-xl border border-dashed border-[var(--color-border)] bg-[var(--color-surface)] px-4 py-8 text-center text-sm text-[var(--color-text-secondary)]">
            No integrations in this category yet.
          </p>
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
