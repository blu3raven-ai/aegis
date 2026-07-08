"use client"

import { Info, TriangleAlert } from "lucide-react"
import { isLocalOrigin } from "@/lib/shared/local-origin"

interface HostReachabilityNoteProps {
  /** The address the URL or command is built from (usually window.location.origin). */
  origin: string
  /** Who must be able to reach the address, e.g. "GitHub" or "the runner machine". */
  audience: string
}

/**
 * Inline callout for integration flows whose address is derived from the
 * browser origin. Warns loudly when that origin is localhost (the external
 * side can't reach it) and otherwise leaves a neutral reachability reminder.
 */
export function HostReachabilityNote({ origin, audience }: HostReachabilityNoteProps) {
  if (isLocalOrigin(origin)) {
    return (
      <div className="flex gap-2 rounded-lg border border-[var(--color-severity-high-border)] bg-[var(--color-severity-high-subtle)] p-3">
        <TriangleAlert
          className="mt-0.5 h-4 w-4 shrink-0 text-[var(--color-severity-high-text)]"
          aria-hidden="true"
        />
        <div className="text-xs text-[var(--color-severity-high-text)]">
          <p className="font-semibold">This address points at localhost</p>
          <p className="mt-0.5">
            {audience} can&apos;t reach{" "}
            <code className="font-mono">{origin}</code>. Expose Aegis at a public URL — a reverse
            proxy (nginx/Caddy) or a tunnel (e.g. cloudflared, ngrok) — and use that address here
            instead.
          </p>
        </div>
      </div>
    )
  }

  return (
    <div className="flex gap-2 rounded-lg border border-[var(--color-border)] bg-[var(--color-surface-raised)] p-3">
      <Info
        className="mt-0.5 h-4 w-4 shrink-0 text-[var(--color-text-tertiary)]"
        aria-hidden="true"
      />
      <p className="text-xs text-[var(--color-text-secondary)]">
        Make sure this address is reachable by {audience}.
      </p>
    </div>
  )
}
