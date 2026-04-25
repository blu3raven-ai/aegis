"use client"

import { useCallback, useEffect, useRef, useState } from "react"
import { useRouter } from "next/navigation"

const ICON_SEARCH =
  "M21 21l-5.197-5.197m0 0A7.5 7.5 0 1 0 5.196 5.196a7.5 7.5 0 0 0 10.607 10.607Z"

interface SearchItem {
  href: string
  label: string
  category: "Tools" | "Sources" | "Settings"
}

const SEARCH_ITEMS: SearchItem[] = [
  { href: "/dependencies/dashboard", label: "Dependency Scanning (SCA)", category: "Tools" },
  { href: "/containers/dashboard", label: "Container Scanning", category: "Tools" },
  { href: "/secrets/dashboard", label: "Secret Scanning", category: "Tools" },
  { href: "/code/dashboard", label: "Code Scanning (SAST)", category: "Tools" },
  // Sources
  { href: "/sources/code-repositories", label: "Git Repository", category: "Sources" },
  { href: "/sources/container-registry", label: "Container Registry", category: "Sources" },
  { href: "/sources/cloud-infrastructure", label: "Cloud Infrastructure", category: "Sources" },
  { href: "/settings/account", label: "Account", category: "Settings" },
  { href: "/settings/users", label: "Members", category: "Settings" },
  { href: "/settings/organisations", label: "Teams", category: "Settings" },
  { href: "/dependencies/dashboard?tab=settings", label: "Dependency Scanning Settings", category: "Settings" },
  { href: "/containers/dashboard?tab=settings", label: "Container Scanning Settings", category: "Settings" },
  { href: "/code/dashboard?tab=settings", label: "Code Scanning Settings", category: "Settings" },
  { href: "/secrets/dashboard?tab=settings", label: "Secret Scanning Settings", category: "Settings" },
  { href: "/settings/iac-security", label: "IaC Security Settings", category: "Settings" },
]

interface SearchModalProps {
  open: boolean
  onClose: () => void
}

export function SearchModal({ open, onClose }: SearchModalProps) {
  const router = useRouter()
  const inputRef = useRef<HTMLInputElement>(null)
  const [query, setQuery] = useState("")
  const [activeIndex, setActiveIndex] = useState(0)

  const filtered = query
    ? SEARCH_ITEMS.filter((item) =>
        item.label.toLowerCase().includes(query.toLowerCase())
      )
    : SEARCH_ITEMS

  // Reset state when modal opens/closes
  useEffect(() => {
    if (open) {
      setQuery("")
      setActiveIndex(0)
      // Small delay so the DOM is ready before focusing
      requestAnimationFrame(() => {
        inputRef.current?.focus()
      })
    }
  }, [open])

  // Global ⌘K listener
  useEffect(() => {
    function handleKeyDown(e: KeyboardEvent) {
      if ((e.metaKey || e.ctrlKey) && e.key === "k") {
        e.preventDefault()
        if (open) {
          onClose()
        }
      }
    }
    window.addEventListener("keydown", handleKeyDown)
    return () => window.removeEventListener("keydown", handleKeyDown)
  }, [open, onClose])

  const navigateAndClose = useCallback(
    (href: string) => {
      onClose()
      router.push(href)
    },
    [onClose, router]
  )

  const handleKeyDown = useCallback(
    (e: React.KeyboardEvent) => {
      if (e.key === "Escape") {
        e.preventDefault()
        onClose()
        return
      }
      if (filtered.length === 0) return
      if (e.key === "ArrowDown") {
        e.preventDefault()
        setActiveIndex((i) => (i + 1) % filtered.length)
      } else if (e.key === "ArrowUp") {
        e.preventDefault()
        setActiveIndex((i) => (i - 1 + filtered.length) % filtered.length)
      } else if (e.key === "Enter") {
        e.preventDefault()
        navigateAndClose(filtered[activeIndex].href)
      }
    },
    [filtered, activeIndex, navigateAndClose, onClose]
  )

  // Reset active index when query changes
  useEffect(() => {
    setActiveIndex(0)
  }, [query])

  if (!open) return null

  // Group filtered results by category
  const grouped = filtered.reduce<Record<string, SearchItem[]>>((acc, item) => {
    ;(acc[item.category] ??= []).push(item)
    return acc
  }, {})
  const categories = Object.keys(grouped) as Array<"Tools" | "Sources" | "Settings">

  // Compute a flat index offset per category for activeIndex mapping
  let runningIndex = 0
  const categoryOffsets: Record<string, number> = {}
  for (const cat of categories) {
    categoryOffsets[cat] = runningIndex
    runningIndex += grouped[cat].length
  }

  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center pt-[20vh]">
      {/* Backdrop */}
      <div
        className="fixed inset-0 bg-black/50"
        onClick={onClose}
        aria-hidden
      />

      {/* Modal */}
      <div className="relative z-10 max-w-lg w-full mx-4 rounded-xl border border-[var(--color-border)] bg-[var(--color-surface)] shadow-2xl overflow-hidden">
        {/* Input */}
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
            placeholder="Search settings, tools, sources…"
            className="flex-1 bg-transparent text-sm text-[var(--color-text-primary)] placeholder:text-[var(--color-text-secondary)] outline-none"
          />
          <kbd className="rounded border border-[var(--color-border)] px-1.5 py-0.5 font-mono text-[10px] text-[var(--color-text-secondary)]">
            Esc
          </kbd>
        </div>

        {/* Results */}
        {filtered.length > 0 ? (
          <div className="max-h-72 overflow-y-auto py-2">
            {categories.map((cat) => (
              <div key={cat}>
                <div className="px-3 py-1.5 text-[10px] font-semibold uppercase tracking-[0.12em] text-[var(--color-text-secondary)]">
                  {cat}
                </div>
                {grouped[cat].map((item, i) => {
                  const flatIndex = categoryOffsets[cat] + i
                  const isActive = flatIndex === activeIndex
                  return (
                    <button
                      key={item.href}
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
                      <span className="shrink-0 text-[10px] text-[var(--color-text-secondary)] opacity-60">
                        {item.category}
                      </span>
                    </button>
                  )
                })}
              </div>
            ))}
          </div>
        ) : (
          <div className="px-3 py-6 text-center text-sm text-[var(--color-text-secondary)]">
            No results found.
          </div>
        )}
      </div>
    </div>
  )
}
