import Link from "next/link"
import { Card } from "@/components/ui/Card"

const FOCUS_RING = "focus-visible:ring-2 focus-visible:ring-[var(--color-accent)] focus-visible:outline-none"

interface EnterpriseGateProps {
  feature: string
  description: string
}

export function EnterpriseGate({ feature, description }: EnterpriseGateProps) {
  return (
    <Card padding="none" className="rounded-2xl p-8">
      <div className="max-w-lg">
        <span className="rounded-full bg-[var(--color-argus-subtle)] px-2.5 py-0.5 text-xs font-semibold text-[var(--color-argus)]">
          Enterprise
        </span>
        <h3 className="mt-3 text-sm font-semibold text-[var(--color-text-primary)]">
          {feature} requires an Enterprise license
        </h3>
        <p className="mt-2 text-sm text-[var(--color-text-secondary)]">
          {description}
        </p>
        <Link
          href="/settings/license"
          className={`mt-4 inline-block rounded-lg border border-[var(--color-argus-border)] px-3 py-1.5 text-sm font-semibold text-[var(--color-argus)] transition-colors hover:bg-[var(--color-argus-subtle)] ${FOCUS_RING}`}
        >
          Upgrade
        </Link>
      </div>
    </Card>
  )
}
