"use client"

import Link from "next/link"

export function CompletionCelebration() {
  return (
    <div className="flex flex-col items-center gap-6 py-12 text-center">
      {/* Success icon */}
      <div className="flex h-20 w-20 items-center justify-center rounded-full bg-emerald-500/10">
        <svg
          className="h-10 w-10 text-emerald-500"
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          strokeWidth={1.5}
          strokeLinecap="round"
          strokeLinejoin="round"
        >
          <path d="M9 12.75 11.25 15 15 9.75M21 12c0 1.268-.63 2.39-1.593 3.068a3.745 3.745 0 0 1-1.043 3.296 3.745 3.745 0 0 1-3.296 1.043A3.745 3.745 0 0 1 12 21c-1.268 0-2.39-.63-3.068-1.593a3.745 3.745 0 0 1-3.296-1.043 3.745 3.745 0 0 1-1.043-3.296A3.745 3.745 0 0 1 3 12c0-1.268.63-2.39 1.593-3.068a3.745 3.745 0 0 1 1.043-3.296 3.745 3.745 0 0 1 3.296-1.043A3.746 3.746 0 0 1 12 3c1.268 0 2.39.63 3.068 1.593a3.746 3.746 0 0 1 3.296 1.043 3.746 3.746 0 0 1 1.043 3.296A3.745 3.745 0 0 1 21 12Z" />
        </svg>
      </div>

      <div className="flex flex-col gap-2">
        <h2 className="text-2xl font-bold text-[var(--color-text-primary)]">You're all set!</h2>
        <p className="text-sm text-[var(--color-text-secondary)]">
          Aegis is configured and ready to protect your repositories. Head to your dashboard to see the results.
        </p>
      </div>

      <Link
        href="/dashboard"
        className="rounded-lg bg-[var(--color-accent)] px-6 py-2.5 text-sm font-semibold text-white transition-opacity hover:opacity-90"
      >
        Go to Dashboard
      </Link>
    </div>
  )
}
