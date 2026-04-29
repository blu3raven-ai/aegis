"use client"

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
      <div className="sticky bottom-0 z-10 flex items-center gap-3 rounded-xl border border-[var(--color-status-ok)] bg-[var(--color-surface)] px-4 py-3 shadow-lg transition-opacity">
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
    <div className="sticky bottom-0 z-10 flex items-center gap-3 rounded-xl border-x border-b border-x-[var(--color-border)] border-b-[var(--color-border)] border-t-2 border-t-[var(--color-accent)] bg-[var(--color-surface)] px-4 py-3 shadow-lg">
      <span className="h-2 w-2 shrink-0 rounded-full bg-[var(--color-accent)]" aria-hidden />
      <span className="flex-1 text-xs text-[var(--color-text-primary)]">{label}</span>
      <button
        type="button"
        onClick={onDiscard}
        disabled={saving}
        className="rounded-lg border border-[var(--color-border)] px-3 py-1.5 text-xs text-[var(--color-text-secondary)] transition-colors hover:bg-[var(--color-surface-raised)] hover:text-[var(--color-text-primary)] disabled:cursor-not-allowed disabled:opacity-50"
      >
        Discard
      </button>
      <button
        type="button"
        onClick={onSave}
        disabled={saving}
        className="flex items-center gap-1.5 rounded-lg bg-[var(--color-accent)] px-3 py-1.5 text-xs font-semibold text-white transition-colors hover:bg-[var(--color-accent-hover)] disabled:cursor-not-allowed disabled:opacity-50"
      >
        {saving && (
          <svg className="h-3 w-3 animate-spin" viewBox="0 0 24 24" fill="none">
            <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
            <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8H4z" />
          </svg>
        )}
        {saving ? "Saving…" : "Save changes"}
      </button>
    </div>
  )
}
