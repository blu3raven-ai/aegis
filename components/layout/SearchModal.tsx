"use client"

import { useCallback, useEffect, useRef, useState } from "react"
import { useRouter } from "next/navigation"
import { search, type SearchHit } from "@/lib/client/search-api"

const ICON_SEARCH =
  "M21 21l-5.197-5.197m0 0A7.5 7.5 0 1 0 5.196 5.196a7.5 7.5 0 0 0 10.607 10.607Z"

// Static navigation shortcuts — shown when the query is empty or typed locally.
// These are kept so the modal stays useful even when the backend is unavailable.
interface NavItem {
  href: string
  label: string
  category: "Tools" | "Sources" | "Settings"
}

const NAV_ITEMS: NavItem[] = [
  { href: "/dependencies/dashboard", label: "Dependency Scanning (SCA)", category: "Tools" },
  { href: "/containers/dashboard", label: "Container Scanning", category: "Tools" },
  { href: "/secrets/dashboard", label: "Secret Scanning", category: "Tools" },
  { href: "/code/dashboard", label: "Code Scanning (SAST)", category: "Tools" },
  { href: "/sources", label: "Sources", category: "Sources" },
  { href: "/settings/account", label: "Account", category: "Settings" },
  { href: "/settings/users", label: "Members", category: "Settings" },
  { href: "/settings/organisations", label: "Teams", category: "Settings" },
  { href: "/settings/fleet", label: "Fleet", category: "Settings" },
  { href: "/settings/integrations", label: "Integrations", category: "Settings" },
  { href: "/dependencies/dashboard?tab=settings", label: "Dependency Scanning Settings", category: "Settings" },
  { href: "/containers/dashboard?tab=settings", label: "Container Scanning Settings", category: "Settings" },
  { href: "/code/dashboard?tab=settings", label: "Code Scanning Settings", category: "Settings" },
  { href: "/secrets/dashboard?tab=settings", label: "Secret Scanning Settings", category: "Settings" },
  { href: "/settings/iac-security", label: "IaC Security Settings", category: "Settings" },
]

// Human-readable group labels for API result types
const GROUP_LABELS: Record<string, string> = {
  findings: "Findings",
  chains: "Attack Chains",
  repos: "Repositories",
  audit_events: "Audit Events",
  destinations: "Destinations",
}

interface FlatResult {
  href: string
  label: string
  subtitle?: string
  category: string
}

interface SearchModalProps {
  open: boolean
  onClose: () => void
}

// Debounce hook — delays committing a value until the caller stops changing it.
function useDebounced<T>(value: T, delayMs: number): T {
  const [debounced, setDebounced] = useState<T>(value)
  useEffect(() => {
    const id = setTimeout(() => setDebounced(value), delayMs)
    return () => clearTimeout(id)
  }, [value, delayMs])
  return debounced
}

type FetchState = "idle" | "loading" | "done" | "error"

export function SearchModal({ open, onClose }: SearchModalProps) {
  const router = useRouter()
  const inputRef = useRef<HTMLInputElement>(null)
  const [query, setQuery] = useState("")
  const [activeIndex, setActiveIndex] = useState(0)
  const [fetchState, setFetchState] = useState<FetchState>("idle")
  const [apiResults, setApiResults] = useState<FlatResult[]>([])
  const [apiGrouped, setApiGrouped] = useState<Record<string, FlatResult[]>>({})

  const debouncedQuery = useDebounced(query, 150)

  // Fetch from the real backend when the debounced query changes
  useEffect(() => {
    const trimmed = debouncedQuery.trim()
    if (!trimmed) {
      setApiResults([])
      setApiGrouped({})
      setFetchState("idle")
      return
    }

    const controller = new AbortController()
    setFetchState("loading")

    search(trimmed, { limit: 50, signal: controller.signal })
      .then((res) => {
        const flat: FlatResult[] = []
        const grouped: Record<string, FlatResult[]> = {}

        for (const [group, hits] of Object.entries(res.grouped)) {
          const groupLabel = GROUP_LABELS[group] ?? group
          const groupItems: FlatResult[] = (hits as SearchHit[]).map((h) => ({
            href: h.href,
            label: h.title,
            subtitle: h.subtitle,
            category: groupLabel,
          }))
          grouped[groupLabel] = groupItems
          flat.push(...groupItems)
        }

        setApiGrouped(grouped)
        setApiResults(flat)
        setFetchState("done")
      })
      .catch((err: unknown) => {
        if ((err as { name?: string }).name === "AbortError") return
        setFetchState("error")
      })

    return () => controller.abort()
  }, [debouncedQuery])

  // Reset state when modal opens
  useEffect(() => {
    if (open) {
      setQuery("")
      setActiveIndex(0)
      setApiResults([])
      setApiGrouped({})
      setFetchState("idle")
      requestAnimationFrame(() => {
        inputRef.current?.focus()
      })
    }
  }, [open])

  // Global Cmd+K / Ctrl+K listener
  useEffect(() => {
    function handleKeyDown(e: KeyboardEvent) {
      if ((e.metaKey || e.ctrlKey) && e.key === "k") {
        e.preventDefault()
        if (open) onClose()
      }
    }
    window.addEventListener("keydown", handleKeyDown)
    return () => window.removeEventListener("keydown", handleKeyDown)
  }, [open, onClose])

  // Reset active index whenever the visible list changes
  useEffect(() => {
    setActiveIndex(0)
  }, [query])

  const navigateAndClose = useCallback(
    (href: string) => {
      onClose()
      router.push(href)
    },
    [onClose, router],
  )

  // Decide what to show
  const hasQuery = query.trim().length > 0
  const isLoading = fetchState === "loading"

  let displayGrouped: Record<string, FlatResult[]>
  let flatList: FlatResult[]

  if (!hasQuery) {
    const navGrouped = NAV_ITEMS.reduce<Record<string, FlatResult[]>>((acc, item) => {
      const grp = item.category as string
      ;(acc[grp] ??= []).push({ href: item.href, label: item.label, category: grp })
      return acc
    }, {})
    displayGrouped = navGrouped
    flatList = NAV_ITEMS.map((i) => ({ href: i.href, label: i.label, category: i.category }))
  } else if (fetchState === "done" && apiResults.length > 0) {
    displayGrouped = apiGrouped
    flatList = apiResults
  } else if (fetchState === "done" && apiResults.length === 0) {
    displayGrouped = {}
    flatList = []
  } else if (fetchState === "error") {
    // API error — fall back to local nav filtering
    const fallback = NAV_ITEMS.filter((i) =>
      i.label.toLowerCase().includes(query.toLowerCase()),
    )
    displayGrouped = fallback.reduce<Record<string, FlatResult[]>>((acc, item) => {
      ;(acc[item.category] ??= []).push({ href: item.href, label: item.label, category: item.category })
      return acc
    }, {})
    flatList = fallback.map((i) => ({ href: i.href, label: i.label, category: i.category }))
  } else {
    // loading or idle mid-debounce — keep previous results to avoid flicker
    displayGrouped = apiGrouped
    flatList = apiResults
  }

  const groups = Object.keys(displayGrouped)

  // Flat index offsets per group for keyboard nav
  let runningIndex = 0
  const groupOffsets: Record<string, number> = {}
  for (const g of groups) {
    groupOffsets[g] = runningIndex
    runningIndex += displayGrouped[g].length
  }

  const handleKeyDown = useCallback(
    (e: React.KeyboardEvent) => {
      if (e.key === "Escape") {
        e.preventDefault()
        onClose()
        return
      }
      if (flatList.length === 0) return
      if (e.key === "ArrowDown") {
        e.preventDefault()
        setActiveIndex((i) => (i + 1) % flatList.length)
      } else if (e.key === "ArrowUp") {
        e.preventDefault()
        setActiveIndex((i) => (i - 1 + flatList.length) % flatList.length)
      } else if (e.key === "Enter") {
        e.preventDefault()
        const item = flatList[activeIndex]
        if (item) navigateAndClose(item.href)
      }
    },
    [flatList, activeIndex, navigateAndClose, onClose],
  )

  if (!open) return null

  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center pt-[20vh]">
      {/* Backdrop */}
      <div className="fixed inset-0 bg-[var(--color-overlay-strong)]" onClick={onClose} aria-hidden />

      {/* Modal */}
      <div className="relative z-10 max-w-lg w-full mx-4 rounded-xl border border-[var(--color-border)] bg-[var(--color-surface)] shadow-2xl overflow-hidden">
        {/* Input row */}
        <div className="flex items-center gap-2 border-b border-[var(--color-border)] px-3 py-2.5">
          <svg
            className="h-4 w-4 shrink-0 text-[var(--color-text-secondary)]"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth={1.8}
            strokeLinecap="round"
            strokeLinejoin="round"
          >
            <path d={ICON_SEARCH} />
          </svg>
          <input
            ref={inputRef}
            type="text"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={handleKeyDown}
            placeholder="Search…"
            className="flex-1 bg-transparent text-sm text-[var(--color-text-primary)] placeholder:text-[var(--color-text-secondary)] outline-none"
          />
          {isLoading && (
            <span className="h-3.5 w-3.5 shrink-0 animate-spin rounded-full border border-[var(--color-border)] border-t-[var(--color-text-secondary)]" />
          )}
          <kbd className="rounded border border-[var(--color-border)] px-1.5 py-0.5 font-mono text-2xs text-[var(--color-text-secondary)]">
            Esc
          </kbd>
        </div>

        {/* Results */}
        {isLoading && flatList.length === 0 ? (
          // Loading skeleton — three placeholder rows
          <div className="py-2 space-y-1 px-3">
            {[1, 2, 3].map((n) => (
              <div key={n} className="flex items-center gap-2.5 py-2">
                <div className="h-3 flex-1 rounded bg-[var(--color-surface-raised)] animate-pulse" />
                <div className="h-3 w-12 rounded bg-[var(--color-surface-raised)] animate-pulse" />
              </div>
            ))}
          </div>
        ) : fetchState === "error" && flatList.length === 0 ? (
          <div className="px-3 py-6 text-center text-sm text-[var(--color-text-secondary)]">
            Search unavailable. Showing local results only.
          </div>
        ) : flatList.length > 0 ? (
          <div className="max-h-72 overflow-y-auto py-2">
            {groups.map((grp) => (
              <div key={grp}>
                <div className="px-3 py-1.5 text-2xs font-semibold uppercase tracking-[0.12em] text-[var(--color-text-secondary)]">
                  {grp}
                </div>
                {displayGrouped[grp].map((item, i) => {
                  const flatIndex = groupOffsets[grp] + i
                  const isActive = flatIndex === activeIndex
                  return (
                    <button
                      key={`${grp}-${item.href}-${i}`}
                      type="button"
                      onClick={() => navigateAndClose(item.href)}
                      onMouseEnter={() => setActiveIndex(flatIndex)}
                      className={`flex w-full items-center gap-2.5 px-3 py-2 text-left text-[13px] transition-colors ${
                        isActive
                          ? "bg-[var(--color-surface-raised)] text-[var(--color-text-primary)]"
                          : "text-[var(--color-text-secondary)] hover:bg-[var(--color-surface-raised)] hover:text-[var(--color-text-primary)]"
                      }`}
                    >
                      <span className="flex-1 truncate">{item.label}</span>
                      {item.subtitle && (
                        <span className="shrink-0 max-w-[120px] truncate text-2xs text-[var(--color-text-secondary)] opacity-60">
                          {item.subtitle}
                        </span>
                      )}
                    </button>
                  )
                })}
              </div>
            ))}
          </div>
        ) : hasQuery ? (
          <div className="px-3 py-6 text-center text-sm text-[var(--color-text-secondary)]">
            No results found.
          </div>
        ) : null}
      </div>
    </div>
  )
}
