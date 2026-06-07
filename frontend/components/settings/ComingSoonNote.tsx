/**
 * Soft empty-state block for placeholder settings sections.
 *
 * Replaces the bare "Coming soon — X will land here." paragraph the four
 * placeholder sections were each rendering. Same shape as the home empty
 * status card so the placeholder visually announces itself as a planned
 * surface rather than a missing UI fragment.
 */

interface ComingSoonNoteProps {
  /** Short label that finishes the sentence: "Coming soon — {topic} will land here." */
  topic: string
}

export function ComingSoonNote({ topic }: ComingSoonNoteProps) {
  return (
    <div className="flex items-center gap-4 rounded-xl border border-dashed border-[var(--color-border)] bg-[var(--color-surface-raised)]/30 p-4">
      <span
        aria-hidden="true"
        className="grid h-9 w-9 shrink-0 place-items-center rounded-lg bg-[var(--color-accent-subtle)] text-[var(--color-accent)]"
      >
        <svg className="h-4 w-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round">
          <circle cx="12" cy="12" r="10" />
          <path d="M12 6v6l4 2" />
        </svg>
      </span>
      <p className="text-sm text-[var(--color-text-secondary)]">
        Coming soon — {topic} will land here.
      </p>
    </div>
  )
}
