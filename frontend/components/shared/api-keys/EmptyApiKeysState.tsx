"use client"

/**
 * Empty state for the API tokens section. Matches the single-line empty card
 * used by Teams so the two surfaces feel consistent. The "Create" action
 * lives in the section header — no duplicate button here.
 */
export function EmptyApiKeysState() {
  return (
    <div className="rounded-lg border border-[var(--color-border)] bg-[var(--color-surface)] p-6 text-sm text-[var(--color-text-secondary)]">
      No API tokens generated yet. Create your first token to authenticate
      CLI tools, CI pipelines, and integrations.
    </div>
  )
}
