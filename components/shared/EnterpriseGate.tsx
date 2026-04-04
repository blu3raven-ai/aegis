import Link from "next/link"

const FOCUS_RING = "focus-visible:ring-2 focus-visible:ring-[var(--color-accent)] focus-visible:outline-none"

interface EnterpriseGateProps {
  feature: string
  description: string
}

export function EnterpriseGate({ feature, description }: EnterpriseGateProps) {
  return (
    <div className="rounded-2xl border border-[var(--color-border)] bg-[var(--color-surface)] p-8">
      <div className="max-w-lg">
        <span className="rounded-full bg-purple-500/10 px-2.5 py-0.5 text-xs font-semibold text-purple-500">
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
          className={`mt-4 inline-block rounded-lg border border-purple-500/20 px-3 py-1.5 text-sm font-semibold text-purple-500 transition-colors hover:bg-purple-500/5 ${FOCUS_RING}`}
        >
          Upgrade
        </Link>
      </div>
    </div>
  )
}
