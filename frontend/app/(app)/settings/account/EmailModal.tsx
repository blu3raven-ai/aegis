"use client"

import { useState, useTransition } from "react"
import { Button } from "@/components/ui/Button"
import { Input } from "@/components/ui/Input"
import { Modal } from "./Modal"
import { apiClient } from "@/lib/client/api-client.ts"
import { ApiClientError } from "@/lib/client/api-client.types.ts"

export function EmailModal({
  open,
  initialEmail,
  onClose,
  onSuccess,
}: {
  open: boolean
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
      try {
        await apiClient("/api/v1/settings/account/email", {
          method: "PATCH",
          body: { email: email.trim() || null },
        })
        onSuccess()
      } catch (err) {
        if (err instanceof ApiClientError) {
          const body = err.body as { error?: string } | null
          setError(body?.error ?? "Failed to update email.")
        } else {
          setError("Failed to update email.")
        }
      }
    })
  }

  return (
    <Modal open={open} title="Change email" onClose={onClose}>
      <form onSubmit={handleSubmit} className="space-y-4">
        <div>
          <label className="mb-1.5 block text-xs font-medium text-[var(--color-text-primary)]">
            Email address
          </label>
          <Input
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            placeholder="you@example.com"
            autoFocus
            autoComplete="email"
          />
          <p className="mt-1.5 text-xs text-[var(--color-text-secondary)]">
            Leave blank to remove your email. You can sign in with email or username.
          </p>
        </div>
        {error && <p className="text-sm text-[var(--color-severity-critical)]">{error}</p>}
        <div className="flex justify-end gap-2">
          <Button variant="secondary" size="md" onClick={onClose}>Cancel</Button>
          <Button type="submit" variant="primary" size="md" isLoading={isPending} disabled={isPending}>
            {isPending ? "Saving..." : "Save"}
          </Button>
        </div>
      </form>
    </Modal>
  )
}
