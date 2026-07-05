"use client"

import { useEffect, useRef, useState } from "react"
import {
  deleteSavedView,
  listSavedViews,
  setSavedViewDefault,
  updateSavedView,
  type SavedView,
} from "@/lib/client/saved-views-api"
import { Button } from "@/components/ui/Button"
import { Input } from "@/components/ui/Input"

export interface ManageViewsPanelProps {
  open: boolean
  onClose: () => void
  /**
   * "popover" (default) anchors `absolute right-0 top-full` to a relative parent —
   * appropriate when triggered from a header button with room to expand below.
   * "modal" renders as a centered overlay with a backdrop — for narrow containers
   * like the inbox sidebar where the popover would clip or overflow.
   */
  variant?: "popover" | "modal"
}

export function ManageViewsPanel({ open, onClose, variant = "popover" }: ManageViewsPanelProps) {
  const [views, setViews] = useState<SavedView[]>([])
  const [error, setError] = useState<string | null>(null)
  const [refresh, setRefresh] = useState(0)
  const [renamingId, setRenamingId] = useState<string | null>(null)
  const [renameValue, setRenameValue] = useState("")
  const rootRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (!open) return
    let active = true
    listSavedViews("findings")
      .then((rows) => { if (active) { setViews(rows); setError(null) } })
      .catch((err) => { if (active) setError(err instanceof Error ? err.message : String(err)) })
    return () => { active = false }
  }, [open, refresh])

  useEffect(() => {
    if (!open) return
    const onKey = (e: KeyboardEvent) => { if (e.key === "Escape") onClose() }
    const onClick = (e: MouseEvent) => {
      if (rootRef.current && !rootRef.current.contains(e.target as Node)) onClose()
    }
    document.addEventListener("keydown", onKey)
    document.addEventListener("mousedown", onClick)
    return () => {
      document.removeEventListener("keydown", onKey)
      document.removeEventListener("mousedown", onClick)
    }
  }, [open, onClose])

  if (!open) return null

  async function handleDelete(v: SavedView) {
    if (!window.confirm(`Delete saved view "${v.name}"?`)) return
    try {
      await deleteSavedView(v.id)
      setRefresh((n) => n + 1)
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    }
  }

  async function handleDefault(v: SavedView) {
    try {
      await setSavedViewDefault(v.id)
      setRefresh((n) => n + 1)
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    }
  }

  function startRename(v: SavedView) {
    setRenamingId(v.id)
    setRenameValue(v.name)
  }

  async function submitRename(v: SavedView) {
    const next = renameValue.trim()
    if (!next || next === v.name) {
      setRenamingId(null)
      return
    }
    try {
      await updateSavedView(v.id, { name: next })
      setRenamingId(null)
      setRefresh((n) => n + 1)
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    }
  }

  const panel = (
    <div
      ref={rootRef}
      role="dialog"
      aria-label="Manage saved views"
      className={
        variant === "modal"
          ? "w-80 rounded-md border border-[var(--color-border)] bg-[var(--color-surface)] p-3 shadow-xl"
          : "absolute right-0 top-full z-50 mt-1 w-80 rounded-md border border-[var(--color-border)] bg-[var(--color-surface)] p-3 shadow-lg"
      }
    >
      <div className="mb-2 flex items-center justify-between">
        <h3 className="text-xs font-semibold uppercase tracking-[0.14em] text-[var(--color-text-tertiary)]">Saved views</h3>
        <Button
          variant="link"
          size="xs"
          onClick={onClose}
        >
          Close
        </Button>
      </div>

      {error && <p className="mb-2 text-2xs text-[var(--color-severity-critical-text)]">{error}</p>}

      {views.length === 0 && (
        <p className="px-1 py-2 text-xs text-[var(--color-text-tertiary)]">No saved views yet.</p>
      )}

      <ul className="flex flex-col gap-2">
        {views.map((v) => (
          <li key={v.id} className="rounded-md border border-[var(--color-border-divider)] px-2 py-2">
            {renamingId === v.id ? (
              <form
                onSubmit={(e) => { e.preventDefault(); submitRename(v) }}
                className="flex items-center gap-2"
              >
                <Input
                  size="sm"
                  type="text"
                  autoFocus
                  value={renameValue}
                  onChange={(e) => setRenameValue(e.target.value)}
                  maxLength={255}
                  className="flex-1"
                />
                <Button
                  type="submit"
                  variant="primary"
                  size="xs"
                  disabled={!renameValue.trim()}
                >
                  Save
                </Button>
                <Button
                  variant="link"
                  size="xs"
                  onClick={() => setRenamingId(null)}
                >
                  Cancel
                </Button>
              </form>
            ) : (
              <>
                <div className="mb-1 text-sm text-[var(--color-text-primary)]">
                  {v.is_default ? `★ ${v.name}` : v.name}
                </div>
                <div className="flex items-center gap-3 text-2xs">
                  <Button
                    variant="link"
                    size="xs"
                    onClick={() => startRename(v)}
                  >
                    Rename
                  </Button>
                  <Button
                    variant="link"
                    size="xs"
                    onClick={() => handleDefault(v)}
                    disabled={v.is_default}
                  >
                    Set as default
                  </Button>
                  <Button
                    variant="link"
                    size="xs"
                    onClick={() => handleDelete(v)}
                    className="text-[var(--color-severity-critical-text)] hover:opacity-80 hover:text-[var(--color-severity-critical-text)]"
                  >
                    Delete
                  </Button>
                </div>
              </>
            )}
          </li>
        ))}
      </ul>
    </div>
  )

  if (variant === "modal") {
    return (
      <div
        role="presentation"
        className="fixed inset-0 z-50 flex items-center justify-center bg-black/40"
        onClick={(e) => { if (e.target === e.currentTarget) onClose() }}
      >
        {panel}
      </div>
    )
  }

  return panel
}
