"use client"

import { useState } from "react"
import { createOrganisationTeam } from "@/lib/client/settings-api"

interface CreateTeamPanelProps {
  open: boolean
  onClose: () => void
  onCreated: () => Promise<void>
}

export function CreateTeamPanel({ open, onClose, onCreated }: CreateTeamPanelProps) {
  const [name, setName] = useState("")
  const [description, setDescription] = useState("")
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState<string | null>(null)

  if (!open) return null

  async function onSubmit(event: React.FormEvent) {
    event.preventDefault()
    setSubmitting(true)
    setError(null)

    const result = await createOrganisationTeam({ name, description })
    if (result.ok) {
      setName("")
      setDescription("")
      await onCreated()
      onClose()
    } else {
      setError(result.error)
    }
    setSubmitting(false)
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-[var(--color-overlay-strong)] p-4">
      <form
        onSubmit={onSubmit}
        className="w-full max-w-md rounded-xl border border-[var(--color-border)] bg-[var(--color-surface)] p-6 shadow-2xl"
      >
        <h2 className="text-xl font-bold text-[var(--color-text-primary)]">Create team</h2>
        <p className="mt-1 text-sm text-[var(--color-text-secondary)]">
          Set up a team first, then assign members, repositories, and container images from the editor.
        </p>

        <div className="mt-6 space-y-4">
          <label className="block space-y-1.5">
            <span className="text-2xs font-bold uppercase tracking-wider text-[var(--color-text-secondary)]">Team name</span>
            <input
              required
              value={name}
              onChange={(event) => setName(event.target.value)}
              autoFocus
              placeholder="Platform"
              className="w-full rounded-lg border border-[var(--color-border)] bg-[var(--color-bg)] px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-[var(--color-accent)]/30"
            />
          </label>
          <label className="block space-y-1.5">
            <span className="text-2xs font-bold uppercase tracking-wider text-[var(--color-text-secondary)]">Description</span>
            <textarea
              value={description}
              onChange={(event) => setDescription(event.target.value)}
              rows={3}
              placeholder="Owns the shared application platform and supporting services."
              className="w-full rounded-lg border border-[var(--color-border)] bg-[var(--color-bg)] px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-[var(--color-accent)]/30"
            />
          </label>
          {error && <p className="rounded-lg border border-[var(--color-severity-critical-border)] bg-[var(--color-severity-critical-subtle)] px-3 py-2 text-sm text-[var(--color-severity-critical)]">{error}</p>}
        </div>

        <div className="mt-5 flex justify-end gap-2">
          <button type="button" onClick={onClose} className="rounded-lg border border-[var(--color-border)] px-4 py-2 text-sm font-semibold hover:bg-[var(--color-surface-raised)]">
            Cancel
          </button>
          <button disabled={submitting} className="rounded-lg bg-[var(--color-accent)] px-4 py-2 text-sm font-semibold text-[var(--color-accent-on)] transition-colors hover:bg-[var(--color-accent-hover)] disabled:opacity-50">
            {submitting ? "Creating..." : "Create team"}
          </button>
        </div>
      </form>
    </div>
  )
}
