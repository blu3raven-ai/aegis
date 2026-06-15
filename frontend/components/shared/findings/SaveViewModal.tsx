"use client"

import { useState } from "react"
import { createSavedView, type SavedView } from "@/lib/client/saved-views-api"
import { Button } from "@/components/ui/Button"
import { Input } from "@/components/ui/Input"
import { Sheet } from "@/components/ui/Sheet"

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
    <Sheet open={open} onClose={onClose} title="Save view" size="sm">
      <form onSubmit={handleSubmit}>
        <label className="flex flex-col gap-1 text-xs text-[var(--color-text-secondary)]">
          Name
          <Input
            type="text"
            autoFocus
            value={name}
            onChange={(e) => setName(e.target.value)}
            maxLength={255}
            placeholder="e.g. Critical KEV in main repo"
          />
        </label>
        {error && <p className="mt-2 text-xs text-[var(--color-severity-critical)]">{error}</p>}
        <div className="mt-4 flex justify-end gap-2">
          <Button variant="secondary" size="sm" onClick={onClose}>
            Cancel
          </Button>
          <Button
            type="submit"
            variant="primary"
            size="sm"
            disabled={!name.trim() || saving}
            isLoading={saving}
          >
            {saving ? "Saving…" : "Save"}
          </Button>
        </div>
      </form>
    </Sheet>
  )
}
