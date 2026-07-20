"use client"

import { useState, useMemo } from "react"
import type { ScanScope } from "@/lib/shared/sources-types"
import { Button } from "@/components/ui/Button"


interface ScopeConfiguratorProps {
  itemLabel: string
  totalCount: number | null
  scanScope: ScanScope
  excludedItems: string[]
  includedItems: string[]
  onScopeChange: (scope: ScanScope) => void
  onExcludedChange: (excluded: string[]) => void
  onIncludedChange: (included: string[]) => void
  availableItems?: string[]
}


export function ScopeConfigurator({
  itemLabel,
  totalCount,
  scanScope,
  excludedItems,
  includedItems,
  onScopeChange,
  onExcludedChange,
  onIncludedChange,
  availableItems,
}: ScopeConfiguratorProps) {
  const [search, setSearch] = useState("")

  const countLabel =
    totalCount != null ? ` (${totalCount.toLocaleString()})` : ""

  const sortedItems = useMemo(() => {
    // Include persisted selections that aren't in the discovered list (e.g. a repo
    // added by URL): otherwise its row never renders and the "N selected" badge
    // points at something the user can't see or un-check.
    const discovered = new Set(availableItems ?? [])
    const all = new Set([...(availableItems ?? []), ...includedItems, ...excludedItems])
    // Pin the added-by-URL items to the top so they're immediately visible rather
    // than sorted into the middle of a long discovered list; alpha within groups.
    return [...all].sort((a, b) => {
      const rank = Number(discovered.has(a)) - Number(discovered.has(b))
      return rank !== 0 ? rank : a.localeCompare(b)
    })
  }, [availableItems, includedItems, excludedItems])

  const filteredItems = useMemo(() => {
    const q = search.trim().toLowerCase()
    return q ? sortedItems.filter((item) => item.toLowerCase().includes(q)) : sortedItems
  }, [sortedItems, search])

  function toggleExcluded(item: string) {
    if (excludedItems.includes(item)) {
      onExcludedChange(excludedItems.filter((i) => i !== item))
    } else {
      onExcludedChange([...excludedItems, item])
    }
  }

  function removeExcluded(item: string) {
    onExcludedChange(excludedItems.filter((i) => i !== item))
  }

  function toggleIncluded(item: string) {
    if (includedItems.includes(item)) {
      onIncludedChange(includedItems.filter((i) => i !== item))
    } else {
      onIncludedChange([...includedItems, item])
    }
  }

  const hasItems = sortedItems.length > 0

  return (
    <div className="flex flex-col gap-4">
      {/* Radio options */}
      <fieldset>
        <legend className="sr-only">Scan scope</legend>
        <div className="flex flex-col gap-3">
          <label className="flex items-start gap-2.5 cursor-pointer">
            <input
              type="radio"
              name="scan-scope"
              value="all"
              checked={scanScope === "all"}
              onChange={() => onScopeChange("all")}
              className="mt-0.5 accent-[var(--color-accent)]"
            />
            <div>
              <span className="text-sm font-medium text-[var(--color-text-primary)]">
                Scan all {itemLabel}{countLabel}
              </span>
              <p className="text-xs text-[var(--color-text-secondary)]">
                Every discovered item will be included in scans.
              </p>
            </div>
          </label>

          <label className="flex items-start gap-2.5 cursor-pointer">
            <input
              type="radio"
              name="scan-scope"
              value="all-except-excluded"
              checked={scanScope === "all-except-excluded"}
              onChange={() => onScopeChange("all-except-excluded")}
              className="mt-0.5 accent-[var(--color-accent)]"
            />
            <div>
              <span className="text-sm font-medium text-[var(--color-text-primary)]">
                Scan all except excluded
                {excludedItems.length > 0 && (
                  <span className="ml-1.5 rounded-full bg-[var(--color-accent-subtle)] px-1.5 py-0.5 text-xs text-[var(--color-accent)]">
                    {excludedItems.length} excluded
                  </span>
                )}
              </span>
              <p className="text-xs text-[var(--color-text-secondary)]">
                Choose specific items to exclude from scanning.
              </p>
            </div>
          </label>

          <label className="flex items-start gap-2.5 cursor-pointer">
            <input
              type="radio"
              name="scan-scope"
              value="selected"
              checked={scanScope === "selected"}
              onChange={() => onScopeChange("selected")}
              className="mt-0.5 accent-[var(--color-accent)]"
            />
            <div>
              <span className="text-sm font-medium text-[var(--color-text-primary)]">
                Scan only selected {itemLabel}
                {includedItems.length > 0 && (
                  <span className="ml-1.5 rounded-full bg-[var(--color-accent-subtle)] px-1.5 py-0.5 text-xs text-[var(--color-accent)]">
                    {includedItems.length} selected
                  </span>
                )}
              </span>
              <p className="text-xs text-[var(--color-text-secondary)]">
                Cherry-pick the exact {itemLabel} to scan. Nothing else is pulled.
              </p>
            </div>
          </label>
        </div>
      </fieldset>

      {/* Item selector — shown for the exclude and cherry-pick modes. */}
      {(scanScope === "all-except-excluded" || scanScope === "selected") && (
        <div className="overflow-hidden rounded-md border border-[var(--color-border)]">
          {/* Search */}
          <div className="border-b border-[var(--color-border)] px-3 py-2">
            <div className="flex items-center gap-2">
              <svg className="h-3.5 w-3.5 shrink-0 text-[var(--color-text-secondary)]" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <circle cx="11" cy="11" r="8" />
                <line x1="21" y1="21" x2="16.65" y2="16.65" />
              </svg>
              <input
                type="text"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                placeholder={`Search ${itemLabel}\u2026`}
                className="w-full bg-transparent text-sm text-[var(--color-text-primary)] outline-none placeholder:text-[var(--color-text-secondary)]"
              />
            </div>
          </div>

          {/* List */}
          <div className="max-h-64 overflow-y-auto">
            {!hasItems ? (
              <p className="px-4 py-6 text-center text-sm text-[var(--color-text-secondary)]">
                No {itemLabel} discovered yet. Run a sync first.
              </p>
            ) : filteredItems.length === 0 ? (
              <p className="px-4 py-6 text-center text-sm text-[var(--color-text-secondary)]">
                No matching {itemLabel}.
              </p>
            ) : (
              <ul>
                {filteredItems.map((item) => {
                  // Cherry-pick mode: checked == included (accent). Exclude mode:
                  // checked == excluded (danger + strikethrough). Same list shell.
                  const selectMode = scanScope === "selected"
                  const active = selectMode
                    ? includedItems.includes(item)
                    : excludedItems.includes(item)
                  return (
                    <li
                      key={item}
                      className={`flex items-center gap-2.5 border-b border-[var(--color-border)] px-3 py-2 transition-colors last:border-b-0 ${
                        active
                          ? selectMode
                            ? "bg-[var(--color-accent-subtle)]"
                            : "bg-[var(--color-severity-critical-subtle)]"
                          : ""
                      }`}
                    >
                      <input
                        id={`scope-${item}`}
                        type="checkbox"
                        checked={active}
                        onChange={() => (selectMode ? toggleIncluded(item) : toggleExcluded(item))}
                        className={`shrink-0 ${selectMode ? "accent-[var(--color-accent)]" : "accent-[var(--color-severity-critical)]"}`}
                      />
                      <label
                        htmlFor={`scope-${item}`}
                        className={`flex-1 cursor-pointer select-none truncate text-sm ${
                          active && !selectMode
                            ? "text-[var(--color-severity-critical-text)] line-through"
                            : "text-[var(--color-text-primary)]"
                        }`}
                      >
                        {item}
                      </label>
                      {!selectMode && active && (
                        <Button
                          variant="link"
                          size="xs"
                          onClick={() => removeExcluded(item)}
                          className="shrink-0 text-xs text-[var(--color-severity-critical-text)] hover:text-[var(--color-severity-critical-text)]"
                          aria-label={`Remove ${item} from exclusions`}
                        >
                          <svg className="h-3.5 w-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                            <line x1="18" y1="6" x2="6" y2="18" />
                            <line x1="6" y1="6" x2="18" y2="18" />
                          </svg>
                        </Button>
                      )}
                    </li>
                  )
                })}
              </ul>
            )}
          </div>
        </div>
      )}
    </div>
  )
}
