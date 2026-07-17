"use client"

import type { CatchUpData } from "@/lib/shared/activity-derivations"
import { relativeTime } from "@/lib/shared/relative-time"
import { Button } from "@/components/ui/Button"

interface CatchUpBannerProps {
  data: CatchUpData
  onDismiss: () => void
}

export function CatchUpBanner({ data, onDismiss }: CatchUpBannerProps) {
  const eventLabel = `${data.total} event${data.total === 1 ? "" : "s"}`
  return (
    <div className="mb-4 flex items-center gap-3.5 rounded-xl border border-[color-mix(in_srgb,var(--color-accent)_22%,transparent)] bg-[color-mix(in_srgb,var(--color-accent)_8%,transparent)] px-4 py-3.5">
      <span
        aria-hidden="true"
        className="grid h-9 w-9 shrink-0 place-items-center rounded-lg bg-[var(--color-accent)] text-[var(--color-accent-on)]"
      >
        <svg className="h-4 w-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round">
          <circle cx="12" cy="12" r="10" />
          <path d="M12 6v6l4 2" />
        </svg>
      </span>
      <div className="min-w-0 flex-1">
        <p className="text-sm font-semibold text-[var(--color-text-primary)]">
          You&apos;ve been away since {relativeTime(data.since)}
        </p>
        <p className="mt-0.5 text-xs text-[var(--color-text-secondary)]">
          <strong className="font-semibold text-[var(--color-text-primary)]">{eventLabel}</strong>
          {data.newFindings > 0 && (
            <>
              {" · "}
              <strong className="font-semibold text-[var(--color-text-primary)]">
                {data.newFindings} new finding{data.newFindings === 1 ? "" : "s"}
              </strong>
              {data.criticalFindings > 0 && <> ({data.criticalFindings} critical)</>}
            </>
          )}
          {data.fixed > 0 && (
            <>
              {" · "}
              <strong className="font-semibold text-[var(--color-text-primary)]">
                {data.fixed} fixed
              </strong>
            </>
          )}
        </p>
      </div>
      <Button
        variant="ghost"
        size="sm"
        iconOnly
        onClick={onDismiss}
        aria-label="Dismiss catch-up banner"
        className="shrink-0"
        leadingIcon={
          <svg
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth={2}
            strokeLinecap="round"
            strokeLinejoin="round"
            aria-hidden="true"
          >
            <path d="M18 6 6 18M6 6l12 12" />
          </svg>
        }
      />

    </div>
  )
}
