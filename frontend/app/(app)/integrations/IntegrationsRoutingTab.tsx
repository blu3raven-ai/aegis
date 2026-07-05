"use client"

import { RoutingRulesPanel } from "@/components/shared/notifications/RoutingRulesPanel"

interface IntegrationsRoutingTabProps {
  // keyHint re-mounts the panel so it re-fetches its own destination list when one is added or removed
  keyHint: number
}

export function IntegrationsRoutingTab({ keyHint }: IntegrationsRoutingTabProps) {
  return (
    <div className="mx-auto max-w-7xl px-6 py-8 space-y-8">
      <section>
        {/* Mock rules-head: title + helper-line side by side */}
        <div className="mb-4 flex items-baseline justify-between gap-3">
          <h2 className="text-base font-semibold text-[var(--color-text-primary)]">Routing rules</h2>
          <p className="text-xs text-[var(--color-text-secondary)]">
            Evaluated top-down · first match wins per channel
          </p>
        </div>
        <RoutingRulesPanel key={keyHint} />
      </section>
    </div>
  )
}
