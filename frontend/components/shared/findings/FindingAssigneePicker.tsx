"use client"

import { useEffect, useRef, useState } from "react"

import {
  listAssignableUsers,
  type AssignableUser,
} from "@/lib/client/findings-api"
import { Button, type ButtonSize } from "@/components/ui/Button"
import { Input } from "@/components/ui/Input"

export interface FindingAssigneePickerProps {
  /** Current selected assignee id, or null when unset. */
  value: string | null
  /** Optional pre-resolved display label for `value`; falls back to the id. */
  valueLabel?: string | null
  onChange: (next: string | null) => void
  /** Field-level label rendered above the trigger. */
  label?: string
  /** Aria id used to associate the trigger with an external label. */
  triggerAriaLabel?: string
  /** Trigger label when `value` is null. Defaults to "Any assignee" (filter context). */
  emptyLabel?: string
  /** Disable the trigger and prevent opening — used while a save is in flight. */
  disabled?: boolean
  /** Trigger size — match the surrounding controls. Defaults to "xs". */
  size?: ButtonSize
}

const SEARCH_DEBOUNCE_MS = 200

export function FindingAssigneePicker({
  value,
  valueLabel,
  onChange,
  label,
  triggerAriaLabel,
  emptyLabel = "Any assignee",
  disabled = false,
  size = "xs",
}: FindingAssigneePickerProps) {
  const [open, setOpen] = useState(false)
  const [query, setQuery] = useState("")
  const [results, setResults] = useState<AssignableUser[]>([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const rootRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (!open) return
    setQuery("")
    setError(null)
  }, [open])

  useEffect(() => {
    if (!open) return
    let cancelled = false
    setLoading(true)
    const handle = setTimeout(async () => {
      try {
        const users = await listAssignableUsers(query || null, 20)
        if (!cancelled) setResults(users)
      } catch (e) {
        if (!cancelled) {
          setError(e instanceof Error ? e.message : "Failed to load users")
          setResults([])
        }
      } finally {
        if (!cancelled) setLoading(false)
      }
    }, SEARCH_DEBOUNCE_MS)
    return () => {
      cancelled = true
      clearTimeout(handle)
    }
  }, [open, query])

  useEffect(() => {
    if (!open) return
    const onClick = (e: MouseEvent) => {
      if (rootRef.current && !rootRef.current.contains(e.target as Node)) setOpen(false)
    }
    const onKey = (e: KeyboardEvent) => {
      // Stop the Escape here (document fires before the Sheet's window listener
      // in the bubble phase) so closing the picker doesn't also close the panel.
      if (e.key === "Escape") {
        e.stopPropagation()
        setOpen(false)
      }
    }
    document.addEventListener("mousedown", onClick)
    document.addEventListener("keydown", onKey)
    return () => {
      document.removeEventListener("mousedown", onClick)
      document.removeEventListener("keydown", onKey)
    }
  }, [open])

  // Remember the label of a just-picked user so the trigger shows their name
  // immediately, before the parent re-fetches a fresh `valueLabel`.
  const [pickedLabel, setPickedLabel] = useState<{ id: string; username: string } | null>(null)
  const resolvedLabel =
    pickedLabel && pickedLabel.id === value ? pickedLabel.username : valueLabel || value
  const triggerLabel = value ? resolvedLabel : emptyLabel

  return (
    <div ref={rootRef} className="relative inline-block">
      {label && (
        <div className="mb-1 text-xs text-[var(--color-text-secondary)]">{label}</div>
      )}
      <Button
        variant="secondary"
        size={size}
        onClick={() => setOpen((prev) => !prev)}
        aria-expanded={open}
        aria-label={triggerAriaLabel || (value ? `Change assignee (${triggerLabel})` : "Select assignee")}
        disabled={disabled}
        className="w-full justify-between"
        trailingIcon={
          <svg
            aria-hidden
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="2.5"
            strokeLinecap="round"
            strokeLinejoin="round"
          >
            <path d="M6 9l6 6 6-6" />
          </svg>
        }
      >
        <span className={value ? "" : "text-[var(--color-text-secondary)]"}>{triggerLabel}</span>
      </Button>
      {open && (
        <div
          role="listbox"
          aria-label="Assignable users"
          className="absolute left-0 top-full z-50 mt-1 w-72 rounded-md border border-[var(--color-border)] bg-[var(--color-surface)] p-2 shadow-lg"
        >
          <Input
            size="sm"
            type="search"
            autoFocus
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search by username or email"
            maxLength={255}
            className="mb-2"
          />
          {value && (
            <button
              type="button"
              role="option"
              aria-selected={false}
              onClick={() => {
                onChange(null)
                setPickedLabel(null)
                setOpen(false)
              }}
              className="mb-1 flex w-full items-center justify-between rounded-md px-2 py-1 text-left text-xs text-[var(--color-text-secondary)] hover:bg-[var(--color-surface-raised)]"
            >
              <span>Clear assignee</span>
              <span aria-hidden>×</span>
            </button>
          )}
          {error && (
            <div role="alert" className="px-2 py-1 text-2xs text-[var(--color-severity-critical-text)]">
              {error}
            </div>
          )}
          {loading && (
            <div className="px-2 py-1 text-2xs text-[var(--color-text-secondary)]">Loading…</div>
          )}
          {!loading && !error && results.length === 0 && (
            <div className="px-2 py-1 text-2xs text-[var(--color-text-secondary)]">No matches</div>
          )}
          <ul className="max-h-60 overflow-y-auto">
            {results.map((u) => {
              const selected = u.id === value
              return (
                <li key={u.id}>
                  <button
                    type="button"
                    role="option"
                    aria-selected={selected}
                    onClick={() => {
                      onChange(u.id)
                      setPickedLabel({ id: u.id, username: u.username })
                      setOpen(false)
                    }}
                    className={`flex w-full flex-col items-start rounded-md px-2 py-1 text-left hover:bg-[var(--color-surface-raised)] ${selected ? "bg-[var(--color-surface-raised)]" : ""}`}
                  >
                    <span className="text-xs text-[var(--color-text-primary)]">{u.username}</span>
                    {u.email && (
                      <span className="text-2xs text-[var(--color-text-secondary)]">{u.email}</span>
                    )}
                  </button>
                </li>
              )
            })}
          </ul>
        </div>
      )}
    </div>
  )
}
