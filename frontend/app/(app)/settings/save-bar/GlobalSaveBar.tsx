"use client"

import { useEffect, useState } from "react"
import { SaveBarContent, useSavedFlash } from "./SaveBarContent"
import { useSaveBarAggregate } from "./SaveBarProvider"

export function GlobalSaveBar() {
  const { anyDirty, anySaving, totalCount, error, saveAll, discardAll } = useSaveBarAggregate()
  const showSaved = useSavedFlash(anySaving, anyDirty, error)

  // Center the bar over the main content area, not the full viewport — the
  // sidebar offsets content to the right, and it can collapse, so track the
  // live <main> bounds rather than assuming a fixed width.
  const [bounds, setBounds] = useState<{ left: number; width: number } | null>(null)
  useEffect(() => {
    const main = document.querySelector("main[data-app-scroll]") as HTMLElement | null
    if (!main) return
    const update = () => {
      const r = main.getBoundingClientRect()
      setBounds({ left: r.left, width: r.width })
    }
    update()
    const ro = new ResizeObserver(update)
    ro.observe(main)
    window.addEventListener("resize", update)
    return () => {
      ro.disconnect()
      window.removeEventListener("resize", update)
    }
  }, [])

  const visible = anyDirty || showSaved || !!error
  if (!visible) return null

  return (
    <div
      className="pointer-events-none fixed bottom-4 z-40 flex justify-center px-4"
      style={bounds ? { left: bounds.left, width: bounds.width } : { left: 0, right: 0 }}
    >
      <div
        role="region"
        aria-label="Unsaved changes"
        className={
          showSaved
            ? "pointer-events-auto flex w-full max-w-3xl items-center rounded-xl border border-[var(--color-status-ok)] bg-[var(--color-surface)] px-4 py-3 shadow-lg"
            : "pointer-events-auto flex w-full max-w-3xl items-center rounded-xl border-x border-b border-x-[var(--color-border)] border-b-[var(--color-border)] border-t-2 border-t-[var(--color-accent)] bg-[var(--color-surface)] px-4 py-3 shadow-lg"
        }
      >
        <SaveBarContent
          anyDirty={anyDirty}
          anySaving={anySaving}
          totalCount={totalCount}
          error={error}
          showSaved={showSaved}
          onDiscard={discardAll}
          onSave={() => void saveAll()}
        />
      </div>
    </div>
  )
}
