"use client"

import { Button } from "@/components/ui/Button"

interface SaveBarProps {
  dirty: boolean
  saved?: boolean
  count?: number
  onSave: () => void
  onDiscard: () => void
  saving?: boolean
}

export function SaveBar({ dirty, saved = false, count, onSave, onDiscard, saving = false }: SaveBarProps) {
  if (saved) {
    return (
      <div className="sticky bottom-0 z-10 flex items-center gap-3 rounded-md border border-[var(--color-status-ok)] bg-[var(--color-surface)] px-4 py-3 shadow-lg transition-opacity">
        <svg className="h-4 w-4 shrink-0 text-[var(--color-status-ok)]" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
          <polyline points="20 6 9 17 4 12" />
        </svg>
        <span className="flex-1 text-xs font-medium text-[var(--color-status-ok)]">Changes Saved!</span>
      </div>
    )
  }

  if (!dirty) return null

  const label = count !== undefined
    ? `${count} unsaved change${count === 1 ? "" : "s"}`
    : "Unsaved changes"

  return (
    <div className="sticky bottom-0 z-10 flex items-center gap-3 rounded-md border-x border-b border-x-[var(--color-border)] border-b-[var(--color-border)] border-t-2 border-t-[var(--color-accent)] bg-[var(--color-surface)] px-4 py-3 shadow-lg">
      <span className="h-2 w-2 shrink-0 rounded-full bg-[var(--color-accent)]" aria-hidden />
      <span className="flex-1 text-xs text-[var(--color-text-primary)]">{label}</span>
      <Button variant="secondary" size="sm" onClick={onDiscard} disabled={saving}>
        Discard
      </Button>
      <Button variant="primary" size="sm" onClick={onSave} disabled={saving} isLoading={saving}>
        {saving ? "Saving…" : "Save changes"}
      </Button>
    </div>
  )
}
