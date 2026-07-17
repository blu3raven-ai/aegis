"use client"

import Link from "next/link"
import { Card } from "@/components/ui/Card"

interface NoSourcesBannerProps {
  sourceLabel: string
  sourceHref: string
  toolLabel: string
}

/**
 * Shown on tool Settings tabs when no source connections exist.
 * Guides the user to add a source before configuring the tool.
 */
export function NoSourcesBanner({ sourceLabel, sourceHref, toolLabel }: NoSourcesBannerProps) {
  return (
    <Card padding="none" className="rounded-2xl p-8 shadow-[var(--shadow-card)]">
      <div className="mx-auto max-w-md text-center">
        {/* Icon */}
        <div className="mx-auto flex h-12 w-12 items-center justify-center rounded-2xl bg-[var(--color-accent)]/10">
          <svg
            className="h-6 w-6 text-[var(--color-accent)]"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth={1.5}
            strokeLinecap="round"
            strokeLinejoin="round"
          >
            <path d="M13.19 8.688a4.5 4.5 0 0 1 1.242 7.244l-4.5 4.5a4.5 4.5 0 0 1-6.364-6.364l1.757-1.757m9.86-2.54a4.5 4.5 0 0 0-1.242-7.244l4.5-4.5a4.5 4.5 0 1 0-6.364 6.364L10.5 8.121" />
          </svg>
        </div>

        <h3 className="mt-4 text-base font-semibold text-[var(--color-text-primary)]">
          Connect a Source to Get Started
        </h3>
        <p className="mt-1.5 text-sm text-[var(--color-text-secondary)]">
          {toolLabel} requires a <strong>{sourceLabel}</strong> connection to scan.
          Add one first, then come back to configure your scanner.
        </p>

        <Link
          href={sourceHref}
          className="mt-5 inline-flex items-center gap-2 rounded-xl bg-[var(--color-accent)] px-5 py-2.5 text-sm font-semibold text-[var(--color-accent-on)] transition-opacity hover:opacity-90"
        >
          <svg
            className="h-4 w-4"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth={2}
            strokeLinecap="round"
            strokeLinejoin="round"
          >
            <path d="M12 4.5v15m7.5-7.5h-15" />
          </svg>
          Add {sourceLabel} Connection
        </Link>
      </div>
    </Card>
  )
}
