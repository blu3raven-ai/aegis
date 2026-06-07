"use client"

import { useState } from "react"
import { createSavedView, type SavedView } from "@/lib/client/saved-views-api"

export interface SaveViewModalProps {
  open: boolean
  onClose: () => void
  currentUrlState: Record<string, string>
  onSaved: (view: SavedView) => void
}

export function SaveViewModal({ open, onClose, currentUrlState, onSaved }: SaveViewModalProps) {
  const [name, setName] = useState("")
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState<string | null>(null)

  if (!open) return null

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    setSaving(true)
    setError(null)
    try {
      const view = await createSavedView({ surface: "findings", name: name.trim(), url_state: currentUrlState })
      onSaved(view)
      setName("")
      onClose()
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setSaving(false)
    }
  }

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-label="Save view"
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/40"
      onClick={(e) => { if (e.target === e.currentTarget) onClose() }}
    >
      <form
        onSubmit={handleSubmit}
        className="w-80 rounded-lg border border-[var(--color-border)] bg-[var(--color-surface)] p-4 shadow-xl"
      >
        <h2 className="text-base font-semibold text-[var(--color-text-primary)]">Save view</h2>
        <label className="mt-3 flex flex-col gap-1 text-xs text-[var(--color-text-secondary)]">
          Name
          <input
            type="text"
            autoFocus
            value={name}
            onChange={(e) => setName(e.target.value)}
            maxLength={255}
            placeholder="e.g. Critical KEV in main repo"
            className="rounded-md border border-[var(--color-border)] bg-[var(--color-bg)] px-2 py-1 text-sm text-[var(--color-text-primary)]"
          />
        </label>
        {error && <p className="mt-2 text-xs text-[var(--color-severity-critical)]">{error}</p>}
        <div className="mt-4 flex justify-end gap-2">
          <button
            type="button"
            onClick={onClose}
            className="rounded-md border border-[var(--color-border)] px-3 py-1 text-xs text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)]"
          >Cancel</button>
          <button
            type="submit"
            disabled={!name.trim() || saving}
            className="rounded-md bg-[var(--color-accent)] px-3 py-1 text-xs font-semibold text-[var(--color-accent-on)] disabled:opacity-50"
          >{saving ? "Saving…" : "Save"}</button>
        </div>
      </form>
    </div>
  )
}
