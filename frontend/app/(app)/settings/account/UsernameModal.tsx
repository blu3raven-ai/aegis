"use client"

import { useState, useTransition } from "react"
import { Button } from "@/components/ui/Button"
import { Input } from "@/components/ui/Input"
import { saveAccountSettings } from "@/lib/client/settings-api"
import { Modal } from "./Modal"

export function UsernameModal({
  open,
  initialUsername,
  onClose,
  onSuccess,
}: {
  open: boolean
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
    <Modal open={open} title="Change username" onClose={onClose}>
      <form onSubmit={handleSubmit} className="space-y-4">
        <div>
          <label className="mb-1.5 block text-xs font-medium text-[var(--color-text-primary)]">
            Username
          </label>
          <Input
            type="text"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            required
            autoFocus
          />
        </div>
        {error && <p className="text-sm text-[var(--color-severity-critical)]">{error}</p>}
        <div className="flex justify-end gap-2">
          <Button variant="secondary" size="md" onClick={onClose}>Cancel</Button>
          <Button type="submit" variant="primary" size="md" isLoading={isPending} disabled={isPending || !username.trim()}>
            {isPending ? "Saving..." : "Save"}
          </Button>
        </div>
      </form>
    </Modal>
  )
}
