"use client"

import { useState, useTransition } from "react"
import { Modal } from "./Modal"

const cancelBtnClass =
  "rounded-lg border border-[var(--color-border)] px-4 py-2 text-sm font-medium text-[var(--color-text-secondary)] transition-colors hover:bg-[var(--color-surface-raised)]"
const saveBtnClass =
  "rounded-lg bg-[var(--color-accent)] px-4 py-2 text-sm font-semibold text-[var(--color-accent-on)] transition-colors hover:bg-[var(--color-accent-hover)] disabled:cursor-not-allowed disabled:opacity-50"

export function EmailModal({
  initialEmail,
  onClose,
  onSuccess,
}: {
  initialEmail: string | null
  onClose: () => void
  onSuccess: () => void
}) {
  const [email, setEmail] = useState(initialEmail ?? "")
  const [error, setError] = useState<string | null>(null)
  const [isPending, startTransition] = useTransition()

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    setError(null)
    startTransition(async () => {
      const res = await fetch("/api/settings/account/email", {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: email.trim() || null }),
      })
      const data = await res.json().catch(() => ({})) as { error?: string }
      if (!res.ok) {
        setError(data.error ?? "Failed to update email.")
        return
      }
      onSuccess()
    })
  }

  return (
    <Modal title="Change email" onClose={onClose}>
      <form onSubmit={handleSubmit} className="space-y-4">
        <div>
          <label className="mb-1.5 block text-xs font-medium text-[var(--color-text-primary)]">
            Email address
          </label>
          <input
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            placeholder="you@example.com"
            autoFocus
            autoComplete="email"
            className="w-full rounded-lg border border-[var(--color-border)] bg-[var(--color-surface)] px-3 py-2.5 text-sm text-[var(--color-text-primary)] placeholder:text-[var(--color-text-secondary)] focus:outline-none focus:ring-2 focus:ring-[var(--color-accent)]/30"
          />
          <p className="mt-1.5 text-xs text-[var(--color-text-secondary)]">
            Leave blank to remove your email. You can sign in with email or username.
          </p>
        </div>
        {error && <p className="text-sm text-red-500">{error}</p>}
        <div className="flex justify-end gap-2">
          <button type="button" onClick={onClose} className={cancelBtnClass}>Cancel</button>
          <button type="submit" disabled={isPending} className={saveBtnClass}>
            {isPending ? "Saving..." : "Save"}
          </button>
        </div>
      </form>
    </Modal>
  )
}
