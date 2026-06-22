"use client"

import { useRef } from "react"
import type { ApiKey } from "@/lib/client/api-keys-api"
import { Button } from "@/components/ui/Button"
import { useDialogA11y } from "@/lib/client/use-dialog-a11y"

interface Props {
  apiKey: ApiKey | null
  onConfirm: () => Promise<void>
  onCancel: () => void
}

export function RevokeKeyConfirmDialog({ apiKey, onConfirm, onCancel }: Props) {
  const dialogRef = useRef<HTMLDivElement>(null)
  useDialogA11y(dialogRef, onCancel, apiKey !== null)

  if (!apiKey) return null

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-[var(--color-overlay-strong)]"
      onClick={onCancel}
    >
      <div
        ref={dialogRef}
        tabIndex={-1}
        onClick={(e) => e.stopPropagation()}
        role="dialog"
        aria-modal="true"
        aria-labelledby="revoke-key-title"
        className="w-full max-w-sm rounded-xl border border-[var(--color-border)] bg-[var(--color-surface)] p-6 shadow-xl focus:outline-none"
      >
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
          <Button
            variant="secondary"
            size="sm"
            onClick={onCancel}
          >
            Cancel
          </Button>
          <Button
            variant="destructive"
            size="sm"
            onClick={onConfirm}
          >
            Revoke
          </Button>
        </div>
      </div>
    </div>
  )
}
