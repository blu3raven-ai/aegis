"use client"

import Link from "next/link"

interface EmptyOverviewBannerProps {
  /** Short headline. Defaults to the standard onboarding nudge. */
  title?: string
  /** Subline explaining what the user will see once data flows in. */
  description?: string
  /** Destination of the primary action. Defaults to /repos. */
  ctaHref?: string
  /** Primary action label. */
  ctaLabel?: string
}

/**
 * Slim CTA banner shown above a dimmed ghost preview of an Overview page
 * (Home, Inbox, Findings, Posture) when the backing data is empty.
 *
 * The ghost preview gives users a sense of what the page will look like
 * once data exists; this banner is the only interactive element above it.
 */
export function EmptyOverviewBanner({
  title = "Connect a source to start seeing data",
  description = "The preview below shows what this page will look like once your first scan completes.",
  ctaHref = "/repos",
  ctaLabel = "Add a source",
}: EmptyOverviewBannerProps) {
  return (
    <div
      role="status"
      className="flex flex-wrap items-center gap-4 rounded-2xl border border-[var(--color-accent)]/30 bg-[var(--color-accent)]/5 px-5 py-4"
    >
      <span
        aria-hidden="true"
        className="grid h-9 w-9 shrink-0 place-items-center rounded-xl bg-[var(--color-accent)]/15 text-[var(--color-accent)]"
      >
        <svg
          className="h-4 w-4"
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          strokeWidth={1.8}
          strokeLinecap="round"
          strokeLinejoin="round"
        >
          <path d="M13.19 8.688a4.5 4.5 0 0 1 1.242 7.244l-4.5 4.5a4.5 4.5 0 0 1-6.364-6.364l1.757-1.757m9.86-2.54a4.5 4.5 0 0 0-1.242-7.244l4.5-4.5a4.5 4.5 0 1 0-6.364 6.364L10.5 8.121" />
        </svg>
      </span>
      <div className="min-w-0 flex-1">
        <p className="text-sm font-semibold text-[var(--color-text-primary)]">{title}</p>
        <p className="mt-0.5 text-xs text-[var(--color-text-secondary)]">{description}</p>
      </div>
      <Link
        href={ctaHref}
        className="inline-flex shrink-0 items-center gap-1.5 rounded-lg bg-[var(--color-accent)] px-3.5 py-2 text-xs font-semibold text-[var(--color-accent-on)] transition-colors hover:bg-[var(--color-accent-hover)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)]"
      >
        {ctaLabel}
        <svg
          className="h-3 w-3"
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          strokeWidth={2.2}
          strokeLinecap="round"
          strokeLinejoin="round"
          aria-hidden="true"
        >
          <path d="m9 18 6-6-6-6" />
        </svg>
      </Link>
    </div>
  )
}

interface GhostPreviewWrapperProps {
  children: React.ReactNode
  /** Optional class names appended to the wrapper. */
  className?: string
}

/**
 * Wraps a dimmed ghost preview of page sections. Renders content at reduced
 * opacity and disables pointer events so users understand the placeholders
 * are illustrative, not interactive.
 */
export function GhostPreviewWrapper({ children, className = "" }: GhostPreviewWrapperProps) {
  return (
    <div
      aria-hidden="true"
      className={`pointer-events-none select-none opacity-40 ${className}`}
    >
      {children}
    </div>
  )
}
