"use client"

import { useEffect, useRef, useState } from "react"

import { updateFindingAssignee } from "@/lib/client/findings-api"
import { Button } from "@/components/ui/Button"
import { Input } from "@/components/ui/Input"

export interface FindingAssigneeEditorProps {
  findingId: string
  currentAssignee: string | null
  onUpdate: (next: string | null) => void
}

export function FindingAssigneeEditor({
  findingId,
  currentAssignee,
  onUpdate,
}: FindingAssigneeEditorProps) {
  const [open, setOpen] = useState(false)
  const [input, setInput] = useState(currentAssignee ?? "")
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const rootRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (open) {
      setInput(currentAssignee ?? "")
      setError(null)
    }
  }, [open, currentAssignee])

  useEffect(() => {
    if (!open) return
    const onClick = (e: MouseEvent) => {
      if (rootRef.current && !rootRef.current.contains(e.target as Node)) setOpen(false)
    }
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setOpen(false)
    }
    document.addEventListener("mousedown", onClick)
    document.addEventListener("keydown", onKey)
    return () => {
      document.removeEventListener("mousedown", onClick)
      document.removeEventListener("keydown", onKey)
    }
  }, [open])

  async function commit(next: string | null) {
    const numericId = Number(findingId)
    if (!Number.isFinite(numericId)) {
      setError("Invalid finding id")
      return
    }
    setSaving(true)
    setError(null)
    try {
      const result = await updateFindingAssignee(numericId, next)
      onUpdate(result.finding.assignee_user_id ?? null)
      setOpen(false)
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to update assignee")
    } finally {
      setSaving(false)
    }
  }

  const label = currentAssignee ?? "Unassigned"

  return (
    <div ref={rootRef} className="relative inline-block">
      <Button
        variant="secondary"
        size="xs"
        onClick={() => setOpen((prev) => !prev)}
        aria-expanded={open}
        aria-label={currentAssignee ? `Change assignee (${currentAssignee})` : "Set assignee"}
        trailingIcon={<span aria-hidden className="text-[var(--color-text-tertiary)]">▾</span>}
      >
        <span className={currentAssignee ? "font-[family-name:var(--font-jetbrains-mono)] text-[11px]" : "text-[var(--color-text-secondary)]"}>
          {label}
        </span>
      </Button>
      {open && (
        <div
          role="dialog"
          aria-label="Set assignee"
          className="absolute left-0 top-full z-50 mt-1 w-64 rounded-md border border-[var(--color-border)] bg-[var(--color-surface)] p-3 shadow-lg"
        >
          <label className="flex flex-col gap-1 text-xs text-[var(--color-text-secondary)]">
            User id
            <Input
              size="sm"
              type="text"
              autoFocus
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter") {
                  e.preventDefault()
                  commit(input.trim() || null)
                }
              }}
              maxLength={255}
              disabled={saving}
              placeholder="user-xxx"
            />
          </label>
          {error && (
            <div role="alert" className="mt-2 text-2xs text-[var(--color-severity-critical)]">
              {error}
            </div>
          )}
          <div className="mt-3 flex items-center justify-end gap-2">
            {currentAssignee && (
              <Button
                variant="secondary"
                size="xs"
                onClick={() => commit(null)}
                disabled={saving}
              >
                Clear
              </Button>
            )}
            <Button
              variant="primary"
              size="xs"
              onClick={() => commit(input.trim() || null)}
              disabled={saving}
              isLoading={saving}
            >
              {saving ? "Saving…" : "Save"}
            </Button>
          </div>
        </div>
      )}
    </div>
  )
}
