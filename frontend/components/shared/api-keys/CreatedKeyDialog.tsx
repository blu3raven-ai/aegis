"use client"

import { useState } from "react"
import { Button } from "@/components/ui/Button"

interface Props {
  token: string
  onClose: () => void
}

export function CreatedKeyDialog({ token, onClose }: Props) {
  const [copied, setCopied] = useState(false)

  async function handleCopy() {
    await navigator.clipboard.writeText(token)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-[var(--color-overlay-strong)]"
      role="dialog"
      aria-modal="true"
      aria-labelledby="created-key-title"
    >
      <div className="w-full max-w-md rounded-xl border border-[var(--color-border)] bg-[var(--color-surface)] p-6 shadow-xl">
        <h2
          id="created-key-title"
          className="mb-2 text-base font-semibold text-[var(--color-text-primary)]"
        >
          API key created
        </h2>

        <div className="mb-4 rounded-md border border-l-2 border-[var(--color-state-pending-border)] border-l-[var(--color-state-pending)] bg-[var(--color-state-pending-subtle)] px-3 py-2 text-xs text-[var(--color-text-primary)]">
          Copy this key now — it will not be shown again.
        </div>

        <div className="mb-4 flex items-center gap-2 rounded-md border border-[var(--color-border)] bg-[var(--color-surface-raised)] px-3 py-2">
          <code className="flex-1 break-all font-mono text-[11px] text-[var(--color-text-primary)]">
            {token}
          </code>
          <Button
            variant="ghost"
            size="xs"
            onClick={handleCopy}
            className="shrink-0 text-[var(--color-accent)] hover:bg-[var(--color-nav-active)] hover:text-[var(--color-accent)]"
          >
            {copied ? "Copied!" : "Copy"}
          </Button>
        </div>

        <div className="flex justify-end">
          <Button
            variant="primary"
            size="sm"
            onClick={onClose}
          >
            Done
          </Button>
        </div>
      </div>
    </div>
  )
}
