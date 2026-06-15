"use client"

import { useEffect, useRef, useState } from "react"
import { Button } from "@/components/ui/Button"
import { useSaveBarAggregate } from "./SaveBarProvider"

const SAVED_FLASH_MS = 2200

export function GlobalSaveBar() {
  const { anyDirty, anySaving, totalCount, error, saveAll, discardAll } = useSaveBarAggregate()
  const [showSaved, setShowSaved] = useState(false)
  const prevSavingRef = useRef(false)
  const savedTimerRef = useRef<number | null>(null)

  // Flash a brief "Changes saved!" state when a save cycle finishes with no
  // remaining dirty sections and no error.
  useEffect(() => {
    const prevSaving = prevSavingRef.current
    prevSavingRef.current = anySaving
    if (prevSaving && !anySaving && !anyDirty && !error) {
      setShowSaved(true)
      if (savedTimerRef.current) window.clearTimeout(savedTimerRef.current)
      savedTimerRef.current = window.setTimeout(() => setShowSaved(false), SAVED_FLASH_MS)
    }
    if (anyDirty && showSaved) setShowSaved(false)
  }, [anySaving, anyDirty, error, showSaved])

  useEffect(() => {
    return () => {
      if (savedTimerRef.current) window.clearTimeout(savedTimerRef.current)
    }
  }, [])

  const visible = anyDirty || showSaved || !!error
  if (!visible) return null

  const label = showSaved
    ? "Changes saved"
    : totalCount > 0
      ? `${totalCount} unsaved change${totalCount === 1 ? "" : "s"}`
      : "Unsaved changes"

  return (
    <div className="pointer-events-none fixed inset-x-0 bottom-4 z-40 flex justify-center px-4">
      <div
        role="region"
        aria-label="Unsaved changes"
        className={
          showSaved
            ? "pointer-events-auto flex w-full max-w-3xl items-center gap-3 rounded-xl border border-[var(--color-status-ok)] bg-[var(--color-surface)] px-4 py-3 shadow-lg"
            : "pointer-events-auto flex w-full max-w-3xl items-center gap-3 rounded-xl border-x border-b border-x-[var(--color-border)] border-b-[var(--color-border)] border-t-2 border-t-[var(--color-accent)] bg-[var(--color-surface)] px-4 py-3 shadow-lg"
        }
      >
        {showSaved ? (
          <svg
            aria-hidden="true"
            className="h-4 w-4 shrink-0 text-[var(--color-status-ok)]"
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
          <span
            aria-hidden="true"
            className="h-2 w-2 shrink-0 rounded-full bg-[var(--color-accent)]"
          />
        )}
        <span
          className={
            showSaved
              ? "flex-1 text-xs font-medium text-[var(--color-status-ok)]"
              : "flex-1 text-xs text-[var(--color-text-primary)]"
          }
        >
          {label}
        </span>
        {!showSaved && (
          <>
            <Button variant="secondary" size="sm" onClick={discardAll} disabled={anySaving}>
              Discard
            </Button>
            <Button
              variant="primary"
              size="sm"
              onClick={() => void saveAll()}
              disabled={anySaving || !anyDirty}
              isLoading={anySaving}
            >
              {anySaving ? "Saving…" : "Save changes"}
            </Button>
          </>
        )}
        {error && !showSaved && (
          <span role="alert" className="ml-2 text-xs text-[var(--color-severity-critical)]">
            {error}
          </span>
        )}
      </div>
    </div>
  )
}
