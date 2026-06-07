"use client"

import { useEffect } from "react"
import Link from "next/link"

export default function Error({
  error,
  reset,
}: {
  error: Error & { digest?: string }
  reset: () => void
}) {
  useEffect(() => {
    console.error(error)
  }, [error])

  return (
    <div className="flex min-h-[60vh] flex-col items-center justify-center gap-4 py-20 text-center">
      <div className="flex h-16 w-16 items-center justify-center rounded-2xl bg-[var(--color-surface-raised)] text-[var(--color-status-danger)]">
        <svg className="h-8 w-8" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.2} strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
          <path d="M12 9v3.75M11.25 16.5h1.5M12 3.75 1.5 21h21L12 3.75Z" />
        </svg>
      </div>
      <div className="flex flex-col gap-1">
        <p className="text-base font-semibold text-[var(--color-text-primary)]">Something went wrong</p>
        <p className="max-w-sm text-sm text-[var(--color-text-secondary)]">
          We couldn&apos;t load releases. Try again, or head back home if the problem persists.
        </p>
      </div>
      <div className="flex gap-2">
        <button
          type="button"
          onClick={reset}
          className="rounded-lg bg-[var(--color-accent)] px-4 py-2 text-sm font-medium text-[var(--color-accent-on)] transition-colors hover:opacity-90 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)]"
        >
          Try again
        </button>
        <Link
          href="/"
          className="rounded-lg border border-[var(--color-border)] bg-[var(--color-surface)] px-4 py-2 text-sm font-medium text-[var(--color-text-secondary)] transition-colors hover:bg-[var(--color-surface-raised)] hover:text-[var(--color-text-primary)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)]"
        >
          Go home
        </Link>
      </div>
    </div>
  )
}
