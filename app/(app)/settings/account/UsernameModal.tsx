"use client"

import { useState, useTransition } from "react"
import { saveAccountSettings } from "@/lib/client/settings-api"
import { Modal } from "./Modal"

const cancelBtnClass =
  "rounded-lg border border-[var(--color-border)] px-4 py-2 text-sm font-medium text-[var(--color-text-secondary)] transition-colors hover:bg-[var(--color-surface-raised)]"
const saveBtnClass =
  "rounded-lg bg-[var(--color-accent)] px-4 py-2 text-sm font-semibold text-[var(--color-accent-on)] transition-colors hover:bg-[var(--color-accent-hover)] disabled:cursor-not-allowed disabled:opacity-50"

export function UsernameModal({
  initialUsername,
  onClose,
  onSuccess,
}: {
  initialUsername: string
  onClose: () => void
  onSuccess: () => void
}) {
  const [username, setUsername] = useState(initialUsername)
  const [error, setError] = useState<string | null>(null)
  const [isPending, startTransition] = useTransition()

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    setError(null)
    startTransition(async () => {
      const result = await saveAccountSettings({ username })
      if (!result.ok) {
        setError(result.error)
        return
      }
      onSuccess()
    })
  }

  return (
    <Modal title="Change username" onClose={onClose}>
      <form onSubmit={handleSubmit} className="space-y-4">
        <div>
          <label className="mb-1.5 block text-xs font-medium text-[var(--color-text-primary)]">
            Username
          </label>
          <input
            type="text"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            required
            autoFocus
            className="w-full rounded-lg border border-[var(--color-border)] bg-[var(--color-surface)] px-3 py-2.5 text-sm text-[var(--color-text-primary)] focus:outline-none focus:ring-2 focus:ring-[var(--color-accent)]/30"
          />
        </div>
        {error && <p className="text-sm text-red-500">{error}</p>}
        <div className="flex justify-end gap-2">
          <button type="button" onClick={onClose} className={cancelBtnClass}>Cancel</button>
          <button type="submit" disabled={isPending || !username.trim()} className={saveBtnClass}>
            {isPending ? "Saving..." : "Save"}
          </button>
        </div>
      </form>
    </Modal>
  )
}
