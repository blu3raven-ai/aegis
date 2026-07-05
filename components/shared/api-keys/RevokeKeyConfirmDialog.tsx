"use client"

import type { ApiKey } from "@/lib/client/api-keys-api"

interface Props {
  apiKey: ApiKey | null
  onConfirm: () => Promise<void>
  onCancel: () => void
}

export function RevokeKeyConfirmDialog({ apiKey, onConfirm, onCancel }: Props) {
  if (!apiKey) return null

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-[var(--color-overlay-strong)]"
      role="dialog"
      aria-modal="true"
      aria-labelledby="revoke-key-title"
    >
      <div className="w-full max-w-sm rounded-xl border border-[var(--color-border)] bg-[var(--color-surface)] p-6 shadow-xl">
        <h2
          id="revoke-key-title"
          className="mb-2 text-base font-semibold text-[var(--color-text-primary)]"
        >
          Revoke key?
        </h2>
        <p className="mb-4 text-sm text-[var(--color-text-secondary)]">
          <strong className="text-[var(--color-text-primary)]">{apiKey.name}</strong> will stop
          working immediately. This cannot be undone.
        </p>
        <div className="flex justify-end gap-2">
          <button
            onClick={onCancel}
            className="rounded-lg border border-[var(--color-border)] px-3 py-1.5 text-xs font-medium text-[var(--color-text-secondary)] hover:bg-[var(--color-surface-raised)] transition-colors"
          >
            Cancel
          </button>
          <button
            onClick={onConfirm}
            className="rounded-lg bg-[var(--color-severity-critical)] px-3 py-1.5 text-xs font-medium text-[var(--color-on-danger)] hover:opacity-90 transition-opacity"
          >
            Revoke
          </button>
        </div>
      </div>
    </div>
  )
}
