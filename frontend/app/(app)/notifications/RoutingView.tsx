"use client"

import { RoutingRulesPanel } from "@/components/shared/notifications/RoutingRulesPanel"

interface RoutingViewProps {
  // keyHint re-mounts the panel so it re-fetches its own destination list when one is added or removed
  keyHint: number
}

export function RoutingView({ keyHint }: RoutingViewProps) {
  return (
    <div className="space-y-8 px-6 py-8">
      <section>
        {/* Mock rules-head: title + helper-line side by side */}
        <div className="mb-4 flex items-baseline justify-between gap-3">
          <h2 className="font-mono text-[11px] font-semibold uppercase tracking-[0.22em] text-[var(--color-text-secondary)]">Routing rules</h2>
          <p className="text-xs text-[var(--color-text-secondary)]">
            Evaluated top-down · first match wins per channel
          </p>
        </div>
        <RoutingRulesPanel key={keyHint} />
      </section>
    </div>
  )
}
