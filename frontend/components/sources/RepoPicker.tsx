"use client"

import { useMemo, useState } from "react"
import { Button } from "@/components/ui/Button"
import { Input } from "@/components/ui/Input"

function ownerOf(item: string): string {
  return item.includes("/") ? item.split("/")[0] : item
}

export interface RepoPickerProps {
  discovered: string[]
  initialSelected?: string[]
  onConfirm: (included: string[]) => void
  isSubmitting?: boolean
}

export function RepoPicker({
  discovered,
  initialSelected = [],
  onConfirm,
  isSubmitting = false,
}: RepoPickerProps) {
  const [query, setQuery] = useState("")
  const [selected, setSelected] = useState<Set<string>>(new Set(initialSelected))
  const [publicUrl, setPublicUrl] = useState("")
  const [urlError, setUrlError] = useState<string | null>(null)
  const [checkingUrl, setCheckingUrl] = useState(false)
  const [collapsed, setCollapsed] = useState<Set<string>>(new Set())

  const newAvailable = useMemo(
    () => discovered.filter((r) => !initialSelected.includes(r)),
    [discovered, initialSelected],
  )

  const groups = useMemo(() => {
    const q = query.trim().toLowerCase()
    const discoveredSet = new Set(discovered)
    const byOwner = new Map<string, string[]>()
    const push = (item: string, owner: string) => {
      if (q && !item.toLowerCase().includes(q)) return
      byOwner.set(owner, [...(byOwner.get(owner) ?? []), item])
    }
    for (const repo of discovered) push(repo, ownerOf(repo))
    // Items added by URL (or pre-selected on re-open) aren't in `discovered` —
    // surface them so they render as rows the user can see and uncheck.
    for (const item of selected) if (!discoveredSet.has(item)) push(item, "Added by URL")
    return [...byOwner.entries()].sort(([a], [b]) => a.localeCompare(b))
  }, [discovered, selected, query])

  function toggle(repo: string) {
    setSelected((prev) => {
      const n = new Set(prev)
      n.has(repo) ? n.delete(repo) : n.add(repo)
      return n
    })
  }

  function toggleGroup(repos: string[], on: boolean) {
    setSelected((prev) => {
      const n = new Set(prev)
      for (const r of repos) on ? n.add(r) : n.delete(r)
      return n
    })
  }

  function toggleCollapse(owner: string) {
    setCollapsed((prev) => {
      const n = new Set(prev)
      n.has(owner) ? n.delete(owner) : n.add(owner)
      return n
    })
  }

  async function addPublicUrl() {
    const url = publicUrl.trim()
    setUrlError(null)
    if (!/^https:\/\/.+/.test(url)) {
      setUrlError("Enter a full https:// clone URL.")
      return
    }
    // Verify a GitHub repo exists (public API, no auth) before adding, so a typo
    // or private/nonexistent repo is caught here. Other hosts pass on format.
    const gh = url.match(/^https:\/\/github\.com\/([^/]+)\/([^/]+?)(?:\.git)?\/?$/)
    if (gh) {
      setCheckingUrl(true)
      try {
        const res = await fetch(`https://api.github.com/repos/${gh[1]}/${gh[2]}`)
        if (res.status === 404) {
          setUrlError("That GitHub repository doesn't exist or is private.")
          return
        }
        if (!res.ok && res.status !== 403) {
          setUrlError("Couldn't verify that repository — check the URL.")
          return
        }
        // 403 == rate-limited; don't block, fall through and add.
      } catch {
        // Transient network error — don't block the add on it.
      } finally {
        setCheckingUrl(false)
      }
    }
    setSelected((prev) => new Set(prev).add(url))
    setPublicUrl("")
  }

  const ownersSelected = new Set([...selected].map(ownerOf)).size

  return (
    <div className="flex h-full flex-col">
      {/* search bar */}
      <div className="shrink-0 border-b border-[var(--color-border)] px-4 py-3">
        <Input
          size="sm"
          type="search"
          placeholder="Search repositories…"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
        />
      </div>

      {/* new repos available banner */}
      {newAvailable.length > 0 && (
        <div className="shrink-0 flex items-center gap-3 border-b border-[var(--color-border)] bg-[var(--color-bg-subtle)] px-4 py-2">
          <p className="flex-1 text-xs text-[var(--color-text-secondary)]">
            {newAvailable.length} new repos available since last sync
          </p>
          <Button
            size="xs"
            variant="secondary"
            onClick={() =>
              setSelected((prev) => {
                const n = new Set(prev)
                for (const r of newAvailable) n.add(r)
                return n
              })
            }
          >
            Add all new
          </Button>
        </div>
      )}

      {/* scrollable groups */}
      <div className="min-h-0 flex-1 overflow-y-auto">
        {groups.length === 0 ? (
          <div className="flex flex-col items-center justify-center gap-2 px-6 py-12 text-center">
            <p className="text-sm text-[var(--color-text-primary)]">No repositories found</p>
            <p className="text-xs text-[var(--color-text-secondary)]">
              The token may have no repo access — check its scopes.
            </p>
          </div>
        ) : (
          groups.map(([owner, repos]) => {
            const allChecked = repos.every((r) => selected.has(r))
            const isCollapsed = collapsed.has(owner)
            return (
              <div key={owner} className="border-b border-[var(--color-border)] last:border-b-0">
                {/* group header */}
                <div className="flex items-center gap-2 px-4 py-2">
                  <button
                    type="button"
                    className="flex flex-1 items-center gap-2 text-left"
                    onClick={() => toggleCollapse(owner)}
                  >
                    <svg
                      className={`h-3.5 w-3.5 shrink-0 text-[var(--color-text-tertiary)] transition-transform ${isCollapsed ? "-rotate-90" : ""}`}
                      viewBox="0 0 16 16"
                      fill="currentColor"
                      aria-hidden="true"
                    >
                      <path d="M4 6l4 4 4-4" stroke="currentColor" strokeWidth="1.5" fill="none" strokeLinecap="round" strokeLinejoin="round" />
                    </svg>
                    <span className="text-xs font-semibold text-[var(--color-text-primary)]">
                      {owner}
                    </span>
                    <span className="text-2xs text-[var(--color-text-tertiary)]">
                      {repos.length}
                    </span>
                  </button>
                  <Button
                    size="xs"
                    variant="ghost"
                    onClick={() => toggleGroup(repos, !allChecked)}
                  >
                    {allChecked ? "Clear all" : "Select all"}
                  </Button>
                </div>

                {/* repo rows */}
                {!isCollapsed && (
                  <ul className="pb-1">
                    {repos.map((repo) => (
                      <li key={repo}>
                        <label className="flex cursor-pointer items-center gap-3 px-6 py-1.5 hover:bg-[var(--color-bg-hover)]">
                          <input
                            type="checkbox"
                            className="h-4 w-4 accent-[var(--color-accent)]"
                            checked={selected.has(repo)}
                            onChange={() => toggle(repo)}
                          />
                          <span className="text-sm text-[var(--color-text-primary)]">{repo}</span>
                        </label>
                      </li>
                    ))}
                  </ul>
                )}
              </div>
            )
          })
        )}
      </div>

      {/* bottom bar */}
      <div className="shrink-0 border-t border-[var(--color-border)] px-4 py-3 space-y-3">
        {/* public URL input */}
        <div>
          <div className="flex items-center gap-2">
            <Input
              size="sm"
              type="url"
              placeholder="Add a public repo by https:// clone URL"
              value={publicUrl}
              onChange={(e) => {
                setPublicUrl(e.target.value)
                if (urlError) setUrlError(null)
              }}
              onKeyDown={(e) => e.key === "Enter" && void addPublicUrl()}
              className="flex-1"
              aria-invalid={urlError ? true : undefined}
            />
            <Button
              size="xs"
              variant="secondary"
              isLoading={checkingUrl}
              disabled={checkingUrl}
              onClick={() => void addPublicUrl()}
            >
              Add URL
            </Button>
          </div>
          {urlError && (
            <p className="mt-1 text-xs text-[var(--color-severity-critical-text)]">{urlError}</p>
          )}
        </div>

        {/* count + confirm */}
        <div className="flex items-center gap-3">
          <p className="flex-1 text-xs text-[var(--color-text-secondary)]">
            {selected.size > 0
              ? `${selected.size} selected across ${ownersSelected} owner${ownersSelected !== 1 ? "s" : ""}`
              : "No repositories selected"}
          </p>
          <Button
            variant="primary"
            size="sm"
            isLoading={isSubmitting}
            disabled={selected.size === 0}
            onClick={() => onConfirm([...selected])}
          >
            Add {selected.size} {selected.size === 1 ? "repository" : "repositories"}
          </Button>
        </div>
      </div>
    </div>
  )
}
