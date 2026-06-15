"use client"

import { useEffect, useRef, useState } from "react"

import type { AttributeDef, EnumOption } from "./types"
import { Button } from "@/components/ui/Button"
import { Input } from "@/components/ui/Input"

export interface ValuePickerProps {
  attribute: AttributeDef
  currentValue: string | null
  onApply: (value: string | null) => void
  onClose: () => void
}

export function ValuePicker({ attribute, currentValue, onApply, onClose }: ValuePickerProps) {
  const rootRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    const onClick = (e: MouseEvent) => {
      if (rootRef.current && !rootRef.current.contains(e.target as Node)) onClose()
    }
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose()
    }
    document.addEventListener("mousedown", onClick)
    document.addEventListener("keydown", onKey)
    return () => {
      document.removeEventListener("mousedown", onClick)
      document.removeEventListener("keydown", onKey)
    }
  }, [onClose])

  return (
    <div
      ref={rootRef}
      role="dialog"
      aria-label={`Set ${attribute.label}`}
      className="absolute left-0 top-full z-50 mt-1 w-64 rounded-md border border-[var(--color-border)] bg-[var(--color-surface)] p-2 shadow-lg"
    >
      <div className="mb-1 px-1 text-2xs font-semibold uppercase tracking-[0.14em] text-[var(--color-text-tertiary)]">
        {attribute.label}
      </div>
      {attribute.type === "enum" && attribute.options && (
        <OptionList options={attribute.options} currentValue={currentValue} onApply={onApply} />
      )}
      {attribute.type === "boolean" && attribute.options && (
        <OptionList options={attribute.options} currentValue={currentValue} onApply={onApply} />
      )}
      {attribute.type === "async-list" && attribute.asyncLoader && (
        <AsyncList loader={attribute.asyncLoader} currentValue={currentValue} onApply={onApply} />
      )}
      {attribute.type === "numeric" && attribute.numeric && (
        <NumericInput
          constraints={attribute.numeric}
          placeholder={attribute.placeholder}
          currentValue={currentValue}
          onApply={onApply}
          onClose={onClose}
        />
      )}
      {attribute.type === "text" && (
        <TextInput
          currentValue={currentValue}
          placeholder={attribute.placeholder ?? ""}
          onApply={onApply}
          onClose={onClose}
        />
      )}
    </div>
  )
}

function OptionList({
  options,
  currentValue,
  onApply,
  searchable = false,
}: {
  options: EnumOption[]
  currentValue: string | null
  onApply: (value: string | null) => void
  searchable?: boolean
}) {
  const [query, setQuery] = useState("")
  const q = query.trim().toLowerCase()
  const filtered = q
    ? options.filter((o) => o.label.toLowerCase().includes(q) || o.value.toLowerCase().includes(q))
    : options

  return (
    <div>
      {searchable && (
        <Input
          size="sm"
          type="search"
          autoFocus
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="Search…"
          maxLength={64}
          className="mb-1"
        />
      )}
      <ul className="max-h-64 overflow-y-auto">
        {filtered.length === 0 ? (
          <li className="px-2 py-1 text-2xs text-[var(--color-text-secondary)]">No matches</li>
        ) : (
          filtered.map((opt) => {
            const selected = opt.value === currentValue
            return (
              <li key={opt.value}>
                <button
                  type="button"
                  role="option"
                  aria-selected={selected}
                  onClick={() => onApply(opt.value)}
                  className={`flex w-full items-center gap-2 rounded-md px-2 py-1.5 text-left text-xs hover:bg-[var(--color-surface-raised)] focus-visible:bg-[var(--color-surface-raised)] focus-visible:outline-none ${
                    selected ? "bg-[var(--color-surface-raised)]" : ""
                  }`}
                >
                  {opt.dotColor && (
                    <span
                      aria-hidden
                      className="inline-block h-2 w-2 rounded-full"
                      style={{ background: opt.dotColor }}
                    />
                  )}
                  <span className="text-[var(--color-text-primary)]">{opt.label}</span>
                  {selected && (
                    <span aria-hidden className="ml-auto text-[var(--color-accent)]">
                      ✓
                    </span>
                  )}
                </button>
              </li>
            )
          })
        )}
      </ul>
    </div>
  )
}

function AsyncList({
  loader,
  currentValue,
  onApply,
}: {
  loader: (query: string) => Promise<EnumOption[]>
  currentValue: string | null
  onApply: (value: string | null) => void
}) {
  const [query, setQuery] = useState("")
  const [results, setResults] = useState<EnumOption[]>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    let cancelled = false
    setLoading(true)
    const handle = setTimeout(async () => {
      try {
        const next = await loader(query)
        if (!cancelled) setResults(next)
      } finally {
        if (!cancelled) setLoading(false)
      }
    }, 200)
    return () => {
      cancelled = true
      clearTimeout(handle)
    }
  }, [loader, query])

  return (
    <div>
      <Input
        size="sm"
        type="search"
        autoFocus
        value={query}
        onChange={(e) => setQuery(e.target.value)}
        placeholder="Search…"
        maxLength={64}
        className="mb-1"
      />
      {loading && (
        <div className="px-2 py-1 text-2xs text-[var(--color-text-secondary)]">Loading…</div>
      )}
      {!loading && results.length === 0 && (
        <div className="px-2 py-1 text-2xs text-[var(--color-text-secondary)]">No matches</div>
      )}
      <ul className="max-h-64 overflow-y-auto">
        {results.map((opt) => {
          const selected = opt.value === currentValue
          return (
            <li key={opt.value}>
              <button
                type="button"
                role="option"
                aria-selected={selected}
                onClick={() => onApply(opt.value)}
                className={`flex w-full items-center gap-2 rounded-md px-2 py-1.5 text-left text-xs hover:bg-[var(--color-surface-raised)] focus-visible:bg-[var(--color-surface-raised)] focus-visible:outline-none ${
                  selected ? "bg-[var(--color-surface-raised)]" : ""
                }`}
              >
                <span className="text-[var(--color-text-primary)]">{opt.label}</span>
                {selected && (
                  <span aria-hidden className="ml-auto text-[var(--color-accent)]">
                    ✓
                  </span>
                )}
              </button>
            </li>
          )
        })}
      </ul>
    </div>
  )
}

function NumericInput({
  constraints,
  placeholder,
  currentValue,
  onApply,
  onClose,
}: {
  constraints: { min: number; max: number; step?: number }
  placeholder?: string
  currentValue: string | null
  onApply: (value: string | null) => void
  onClose: () => void
}) {
  const [draft, setDraft] = useState(currentValue ?? "")
  const [error, setError] = useState<string | null>(null)

  const commit = () => {
    if (draft.trim() === "") {
      onApply(null)
      onClose()
      return
    }
    const parsed = Number(draft)
    if (!Number.isFinite(parsed) || parsed < constraints.min || parsed > constraints.max) {
      setError(`Enter a number between ${constraints.min} and ${constraints.max}`)
      return
    }
    onApply(String(parsed))
    onClose()
  }

  return (
    <div className="p-1">
      <label className="mb-1 block text-2xs text-[var(--color-text-secondary)]">
        Minimum value (≥ threshold)
      </label>
      <Input
        size="sm"
        type="number"
        autoFocus
        value={draft}
        onChange={(e) => {
          setDraft(e.target.value)
          setError(null)
        }}
        onKeyDown={(e) => {
          if (e.key === "Enter") commit()
        }}
        min={constraints.min}
        max={constraints.max}
        step={constraints.step}
        placeholder={placeholder}
      />
      {error && (
        <div role="alert" className="mt-1 text-2xs text-[var(--color-severity-critical)]">
          {error}
        </div>
      )}
      <div className="mt-2 flex justify-end gap-1">
        <Button
          variant="ghost"
          size="xs"
          onClick={onClose}
        >
          Cancel
        </Button>
        <Button
          variant="primary"
          size="xs"
          onClick={commit}
        >
          Apply
        </Button>
      </div>
    </div>
  )
}

function TextInput({
  currentValue,
  placeholder,
  onApply,
  onClose,
}: {
  currentValue: string | null
  placeholder: string
  onApply: (value: string | null) => void
  onClose: () => void
}) {
  const [draft, setDraft] = useState(currentValue ?? "")

  const commit = () => {
    const trimmed = draft.trim()
    onApply(trimmed === "" ? null : trimmed)
    onClose()
  }

  return (
    <div className="p-1">
      <Input
        size="sm"
        type="text"
        autoFocus
        value={draft}
        onChange={(e) => setDraft(e.target.value)}
        onKeyDown={(e) => {
          if (e.key === "Enter") commit()
        }}
        placeholder={placeholder}
        maxLength={64}
      />
      <div className="mt-2 flex justify-end gap-1">
        <Button
          variant="ghost"
          size="xs"
          onClick={onClose}
        >
          Cancel
        </Button>
        <Button
          variant="primary"
          size="xs"
          onClick={commit}
        >
          Apply
        </Button>
      </div>
    </div>
  )
}
