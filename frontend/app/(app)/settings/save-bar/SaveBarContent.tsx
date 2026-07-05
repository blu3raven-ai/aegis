"use client"

import { useEffect, useRef, useState } from "react"
import { Button } from "@/components/ui/Button"

const SAVED_FLASH_MS = 2200

/** Brief "Changes saved" flash after a save cycle finishes clean. Shared by the
 *  page-level GlobalSaveBar and the in-modal ModalSaveFooter so both behave
 *  identically. */
export function useSavedFlash(anySaving: boolean, anyDirty: boolean, error: string | null): boolean {
  const [showSaved, setShowSaved] = useState(false)
  const prevSavingRef = useRef(false)
  const timerRef = useRef<number | null>(null)

  useEffect(() => {
    const prevSaving = prevSavingRef.current
    prevSavingRef.current = anySaving
    if (prevSaving && !anySaving && !anyDirty && !error) {
      setShowSaved(true)
      if (timerRef.current) window.clearTimeout(timerRef.current)
      timerRef.current = window.setTimeout(() => setShowSaved(false), SAVED_FLASH_MS)
    }
    if (anyDirty && showSaved) setShowSaved(false)
  }, [anySaving, anyDirty, error, showSaved])

  useEffect(() => {
    return () => {
      if (timerRef.current) window.clearTimeout(timerRef.current)
    }
  }, [])

  return showSaved
}

export interface SaveBarContentProps {
  anyDirty: boolean
  anySaving: boolean
  totalCount: number
  error: string | null
  showSaved: boolean
  onDiscard: () => void
  onSave: () => void
}

/** The status dot/label + Discard/Save row shared by the page bar and the modal
 *  footer. Renders only the row — the container chrome (floating pill vs Dialog
 *  footer) is the caller's. */
export function SaveBarContent({
  anyDirty,
  anySaving,
  totalCount,
  error,
  showSaved,
  onDiscard,
  onSave,
}: SaveBarContentProps) {
  const label = showSaved
    ? "Changes saved"
    : totalCount > 0
      ? `${totalCount} unsaved change${totalCount === 1 ? "" : "s"}`
      : "Unsaved changes"

  return (
    <div className="flex w-full items-center gap-3">
      {showSaved ? (
        <svg
          aria-hidden="true"
          className="h-4 w-4 shrink-0 text-[var(--color-status-ok-text)]"
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          strokeWidth="2.5"
          strokeLinecap="round"
          strokeLinejoin="round"
        >
          <polyline points="20 6 9 17 4 12" />
        </svg>
      ) : (
        <span aria-hidden="true" className="h-2 w-2 shrink-0 rounded-full bg-[var(--color-accent)]" />
      )}
      <span
        className={
          showSaved
            ? "flex-1 text-xs font-medium text-[var(--color-status-ok-text)]"
            : "flex-1 text-xs text-[var(--color-text-primary)]"
        }
      >
        {label}
      </span>
      {!showSaved && (
        <>
          <Button variant="secondary" size="sm" onClick={onDiscard} disabled={anySaving}>
            Discard
          </Button>
          <Button
            variant="primary"
            size="sm"
            onClick={onSave}
            disabled={anySaving || !anyDirty}
            isLoading={anySaving}
          >
            {anySaving ? "Saving…" : "Save changes"}
          </Button>
        </>
      )}
      {error && !showSaved && (
        <span role="alert" className="ml-2 text-xs text-[var(--color-severity-critical-text)]">
          {error}
        </span>
      )}
    </div>
  )
}
