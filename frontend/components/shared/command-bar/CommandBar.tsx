"use client"

import { useEffect, useMemo, useRef, useState, type KeyboardEvent as ReactKeyboardEvent } from "react"

import { FilterChip } from "./FilterChip"
import { ValuePicker } from "./ValuePicker"
import type { AttributeDef, CommandBarProps } from "./types"

type OpenPicker = string | "typeahead" | null

export function CommandBar({
  attributes,
  values,
  onChange,
  searchInput,
  onSearchInputChange,
  onSearchSubmit,
  searchPlaceholder,
  displayOverflow,
  customPickers,
}: CommandBarProps) {
  const [openPicker, setOpenPicker] = useState<OpenPicker>(null)
  const [highlightedIdx, setHighlightedIdx] = useState(-1)
  const typeaheadRef = useRef<HTMLDivElement>(null)
  const inputRef = useRef<HTMLInputElement>(null)

  const attributeMap = useMemo(() => {
    const map = new Map<string, AttributeDef>()
    for (const a of attributes) map.set(a.key, a)
    return map
  }, [attributes])

  const usedKeys = useMemo(() => {
    const set = new Set<string>()
    for (const a of attributes) {
      if (values[a.key] != null) set.add(a.key)
    }
    return set
  }, [attributes, values])

  const activeAttrs = useMemo(
    () => attributes.filter((a) => values[a.key] != null),
    [attributes, values],
  )

  // When a typeahead pick opens a value picker for an attribute that doesn't yet have a
  // value, surface a placeholder chip so the picker has something to anchor to and the
  // user can see what they're configuring.
  const pendingPickAttr = useMemo(() => {
    if (!openPicker || openPicker === "typeahead") return null
    if (values[openPicker] != null) return null // already an active chip
    return attributeMap.get(openPicker) ?? null
  }, [openPicker, values, attributeMap])

  const renderedAttrs = useMemo(
    () => (pendingPickAttr ? [...activeAttrs, pendingPickAttr] : activeAttrs),
    [activeAttrs, pendingPickAttr],
  )

  const typeaheadQuery = (searchInput ?? "").trim().toLowerCase()
  const typeaheadMatches = useMemo(() => {
    const available = attributes.filter((a) => !usedKeys.has(a.key))
    if (!typeaheadQuery) return available
    return available.filter(
      (a) =>
        a.label.toLowerCase().includes(typeaheadQuery) ||
        a.description.toLowerCase().includes(typeaheadQuery),
    )
  }, [attributes, typeaheadQuery, usedKeys])

  // Show the dropdown whenever the typeahead is open and there's something to render —
  // either the matches themselves OR the no-results message (only meaningful with a query).
  const showTypeahead =
    openPicker === "typeahead" && (typeaheadMatches.length > 0 || typeaheadQuery !== "")

  const activeOptionId =
    showTypeahead && highlightedIdx >= 0 && typeaheadMatches[highlightedIdx]
      ? `command-bar-typeahead-option-${highlightedIdx}`
      : undefined

  // Outside-click handler closes the typeahead while leaving the search input value alone.
  useEffect(() => {
    if (!showTypeahead) return
    const onClick = (e: MouseEvent) => {
      const target = e.target as Node
      const insideDropdown = typeaheadRef.current?.contains(target)
      const insideInput = inputRef.current?.contains(target)
      if (!insideDropdown && !insideInput) setOpenPicker(null)
    }
    document.addEventListener("mousedown", onClick)
    return () => document.removeEventListener("mousedown", onClick)
  }, [showTypeahead])

  // Keep the highlight in range and auto-select the first match while the user is typing,
  // so Enter / Tab can accept it without an arrow-key dance.
  useEffect(() => {
    if (typeaheadMatches.length === 0) {
      if (highlightedIdx !== -1) setHighlightedIdx(-1)
      return
    }
    if (highlightedIdx >= typeaheadMatches.length) {
      setHighlightedIdx(typeaheadMatches.length - 1)
      return
    }
    if (typeaheadQuery && highlightedIdx < 0) {
      setHighlightedIdx(0)
    }
  }, [typeaheadMatches.length, highlightedIdx, typeaheadQuery])

  const handlePickAttribute = (key: string) => {
    const def = attributeMap.get(key)
    if (!def) return
    // Boolean attributes immediately apply "true" — no value picker step.
    if (def.type === "boolean") {
      onChange(key, "true")
      setOpenPicker(null)
      return
    }
    setOpenPicker(key)
  }

  const handleTypeaheadPick = (key: string) => {
    onSearchInputChange?.("")
    setHighlightedIdx(-1)
    handlePickAttribute(key)
  }

  const handleSearchChange = (next: string) => {
    onSearchInputChange?.(next)
    setHighlightedIdx(-1)
    setOpenPicker("typeahead")
  }

  const handleSearchKeyDown = (e: ReactKeyboardEvent<HTMLInputElement>) => {
    if (e.key === "ArrowDown" && typeaheadMatches.length > 0) {
      e.preventDefault()
      setOpenPicker("typeahead")
      setHighlightedIdx((i) => Math.min(i + 1, typeaheadMatches.length - 1))
      return
    }
    if (e.key === "ArrowUp" && typeaheadMatches.length > 0) {
      e.preventDefault()
      setHighlightedIdx((i) => Math.max(i - 1, -1))
      return
    }
    if (e.key === "Escape") {
      if (openPicker === "typeahead") {
        setOpenPicker(null)
        setHighlightedIdx(-1)
      }
      return
    }
    if (e.key === "Enter") {
      // When there's a query, treat the first match as the implicit selection so the user
      // can accept it without arrow-down. Without a query (just-focused state), require an
      // explicit highlight to avoid accidental picks.
      const idx =
        highlightedIdx >= 0
          ? highlightedIdx
          : showTypeahead && typeaheadQuery
            ? 0
            : -1
      if (idx >= 0 && typeaheadMatches[idx]) {
        e.preventDefault()
        handleTypeaheadPick(typeaheadMatches[idx].key)
        return
      }
      onSearchSubmit?.()
    }
  }

  const chipDisplayValue = (def: AttributeDef, raw: string): string => {
    if (def.displayValue) return def.displayValue(raw)
    if (def.options) {
      const match = def.options.find((o) => o.value === raw)
      if (match) return match.label
    }
    return raw
  }

  const isSearchEnabled = onSearchInputChange != null

  return (
    <div className="flex items-center gap-2">
      <div className="relative flex flex-1 flex-wrap items-center gap-1.5 rounded-md border border-[var(--color-border)] bg-[var(--color-surface)] px-3 py-2 focus-within:border-[var(--color-accent)]">
        <svg
          aria-hidden
          className="h-4 w-4 shrink-0 text-[var(--color-text-tertiary)]"
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          strokeWidth="2"
          strokeLinecap="round"
          strokeLinejoin="round"
        >
          <circle cx="11" cy="11" r="7" />
          <path d="m21 21-4.3-4.3" />
        </svg>

        {renderedAttrs.map((def) => {
          const raw = values[def.key] ?? null
          const isPending = raw == null
          const isActive = openPicker === def.key
          const isBoolean = def.type === "boolean"
          const CustomPicker = customPickers?.[def.key]
          return (
            <span key={def.key} className="relative inline-flex">
              <FilterChip
                field={def.label}
                value={isPending ? null : chipDisplayValue(def, raw)}
                variant={def.variant ?? "default"}
                isActive={isActive}
                onClickBody={() => {
                  if (isBoolean) return
                  setOpenPicker((p) => (p === def.key ? null : def.key))
                }}
                onRemove={() => {
                  if (isPending) {
                    // No value committed yet — just dismiss the placeholder.
                    setOpenPicker(null)
                  } else {
                    onChange(def.key, null)
                  }
                }}
              />
              {isActive && !isBoolean && (
                CustomPicker ? (
                  <CustomPicker
                    value={raw}
                    onApply={(next) => {
                      onChange(def.key, next)
                      setOpenPicker(null)
                    }}
                    onClose={() => setOpenPicker(null)}
                  />
                ) : (
                  <ValuePicker
                    attribute={def}
                    currentValue={raw}
                    onApply={(next) => {
                      onChange(def.key, next)
                      setOpenPicker(null)
                    }}
                    onClose={() => setOpenPicker(null)}
                  />
                )
              )}
            </span>
          )
        })}

        {isSearchEnabled && (
          <input
            ref={inputRef}
            type="search"
            value={searchInput ?? ""}
            onChange={(e) => handleSearchChange(e.target.value)}
            onKeyDown={handleSearchKeyDown}
            onFocus={() => setOpenPicker("typeahead")}
            placeholder={searchPlaceholder ?? "Search or add a filter…"}
            aria-label="Search"
            aria-autocomplete="list"
            aria-expanded={showTypeahead}
            aria-controls={showTypeahead ? "command-bar-typeahead" : undefined}
            aria-activedescendant={activeOptionId}
            className="min-w-[160px] flex-1 bg-transparent text-sm text-[var(--color-text-primary)] placeholder:text-[var(--color-text-tertiary)] focus:outline-none focus-visible:outline-none"
          />
        )}

        {showTypeahead && (
          <div
            ref={typeaheadRef}
            id="command-bar-typeahead"
            role="listbox"
            aria-label="Filters"
            className="absolute left-0 right-0 top-full z-50 mt-1 rounded-md border border-[var(--color-border)] bg-[var(--color-surface)] p-1 shadow-lg"
          >
            {typeaheadMatches.length > 0 ? (
              <>
                <div className="px-2 pb-1 pt-2 text-2xs font-semibold uppercase tracking-[0.14em] text-[var(--color-text-tertiary)]">
                  Add filter
                </div>
                <ul>
                  {typeaheadMatches.map((def, idx) => {
                    const highlighted = idx === highlightedIdx
                    return (
                      <li key={def.key}>
                        <button
                          id={`command-bar-typeahead-option-${idx}`}
                          type="button"
                          role="option"
                          aria-selected={highlighted}
                          onMouseEnter={() => setHighlightedIdx(idx)}
                          onClick={() => handleTypeaheadPick(def.key)}
                          className={`flex w-full items-center gap-2 rounded-md px-2 py-1.5 text-left text-xs ${
                            highlighted ? "bg-[var(--color-surface-raised)]" : ""
                          } hover:bg-[var(--color-surface-raised)]`}
                        >
                          <span className="min-w-[88px] font-mono text-xs text-[var(--color-accent)]">
                            {def.label}
                          </span>
                          <span className="text-2xs text-[var(--color-text-secondary)]">
                            {def.description}
                          </span>
                        </button>
                      </li>
                    )
                  })}
                </ul>
                {typeaheadQuery && (
                  <div className="border-t border-[var(--color-border)] px-2 pt-1.5 text-2xs text-[var(--color-text-tertiary)]">
                    <span className="font-mono">↵</span> to search for{" "}
                    <span className="text-[var(--color-text-secondary)]">
                      &quot;{searchInput}&quot;
                    </span>
                  </div>
                )}
              </>
            ) : (
              <div
                role="status"
                aria-live="polite"
                className="px-2 py-2 text-2xs text-[var(--color-text-secondary)]"
              >
                No matching filters.{" "}
                <span className="text-[var(--color-text-tertiary)]">
                  Press <span className="font-mono">↵</span> to search for{" "}
                  <span className="text-[var(--color-text-secondary)]">
                    &quot;{searchInput}&quot;
                  </span>{" "}
                  instead.
                </span>
              </div>
            )}
          </div>
        )}
      </div>

      {displayOverflow}
    </div>
  )
}
