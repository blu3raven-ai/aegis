import Link from "next/link"
import type { Tier } from "@/lib/shared/license/types"
import { TIER_LABELS } from "@/lib/shared/license/types"
import { Card } from "@/components/ui/Card"

interface UpgradeBannerProps {
  requiredTier: Tier
  feature: string
}

export function UpgradeBanner({ requiredTier, feature }: UpgradeBannerProps) {
  return (
    <Card padding="none" className="rounded-md px-6 py-10 text-center">
      <div className="mx-auto mb-3 flex h-10 w-10 items-center justify-center rounded-xl bg-[var(--color-accent)]/10">
        <svg className="h-5 w-5 text-[var(--color-accent)]" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
          <path d="M16.5 10.5V6.75a4.5 4.5 0 1 0-9 0v3.75m-.75 11.25h10.5a2.25 2.25 0 0 0 2.25-2.25v-6.75a2.25 2.25 0 0 0-2.25-2.25H6.75a2.25 2.25 0 0 0-2.25 2.25v6.75a2.25 2.25 0 0 0 2.25 2.25Z" />
        </svg>
      </div>
      <p className="text-sm font-semibold text-[var(--color-text-primary)]">
        {feature}
      </p>
      <p className="mt-1.5 text-xs text-[var(--color-text-secondary)]">
        Upgrade to {TIER_LABELS[requiredTier]} to unlock this feature.
      </p>
      <Link
        href="/settings/license"
        className="mt-4 inline-flex items-center gap-1.5 rounded-lg bg-[var(--color-accent)] px-4 py-2 text-xs font-semibold text-[var(--color-accent-on)] transition-colors hover:bg-[var(--color-accent-hover)]"
      >
        Upgrade plan
      </Link>
    </Card>
  )
}
