"use client"

import { useEffect, type ReactNode } from "react"
import Link from "next/link"
import { Button } from "@/components/ui/Button"

interface PageErrorFallbackProps {
  /** The error thrown inside the route. Logged to the console on mount. */
  error: Error & { digest?: string }
  /** Re-runs the route's render — provided by the Next.js error boundary. */
  reset: () => void
  /** Override the body copy. Default = "We couldn't render this page…". */
  description?: ReactNode
  /** Override the secondary link. Default = home. */
  secondaryAction?: { href: string; label: string }
}

const DEFAULT_DESCRIPTION =
  "We couldn't render this page. Try again, or head back home if the problem persists."

const DEFAULT_SECONDARY = { href: "/", label: "Go home" }

/**
 * Centered "Something went wrong" panel used by every (app)/**\/error.tsx
 * boundary so the same chrome doesn't drift across 10+ copies. The
 * canonical Button primitive is wired for the primary "Try again" CTA; the
 * secondary action stays a next/link Link styled to match the Button
 * secondary geometry so middle-click / open-in-new-tab semantics survive.
 */
export function PageErrorFallback({
  error,
  reset,
  description = DEFAULT_DESCRIPTION,
  secondaryAction = DEFAULT_SECONDARY,
}: PageErrorFallbackProps) {
  useEffect(() => {
    console.error(error)
  }, [error])

  return (
    <div className="flex min-h-[60vh] flex-col items-center justify-center gap-4 py-20 text-center">
      <div className="flex h-16 w-16 items-center justify-center rounded-2xl bg-[var(--color-surface-raised)] text-[var(--color-severity-critical)]">
        <svg
          className="h-8 w-8"
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          strokeWidth={1.2}
          strokeLinecap="round"
          strokeLinejoin="round"
          aria-hidden="true"
        >
          <path d="M12 9v3.75M11.25 16.5h1.5M12 3.75 1.5 21h21L12 3.75Z" />
        </svg>
      </div>
      <div className="flex flex-col gap-1">
        <p className="text-base font-semibold text-[var(--color-text-primary)]">
          Something went wrong
        </p>
        <p className="max-w-sm text-sm text-[var(--color-text-secondary)]">
          {description}
        </p>
      </div>
      <div className="flex gap-2">
        <Button variant="primary" size="md" onClick={reset}>
          Try again
        </Button>
        <Link
          href={secondaryAction.href}
          className="inline-flex h-9 items-center gap-1.5 rounded-md border border-[var(--color-border)] bg-[var(--color-surface)] px-3.5 text-sm font-semibold text-[var(--color-text-primary)] transition-colors hover:border-[var(--color-border-strong)] hover:bg-[var(--color-bg-hover)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)] focus-visible:ring-offset-2 focus-visible:ring-offset-[var(--color-surface)]"
        >
          {secondaryAction.label}
        </Link>
      </div>
    </div>
  )
}
