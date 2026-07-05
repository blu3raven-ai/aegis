"use client"

import { useEffect, useRef, useState } from "react"
import { usePathname } from "next/navigation"
import { fetchCurrentUser, type CurrentUser } from "@/lib/client/auth"
import { ROLE_LABELS } from "@/lib/shared/auth/roles.ts"

type Variant = "header" | "footer"

interface UserMenuButtonProps {
  /** Layout variant: "header" for AppHeader, "footer" for AppSidebar footer */
  variant: Variant
  /** Only for footer variant: whether the sidebar is collapsed */
  collapsed?: boolean
}

export function UserMenuButton({ variant, collapsed = false }: UserMenuButtonProps) {
  const pathname = usePathname()
  const [user, setUser] = useState<CurrentUser | null>(null)
  const [open, setOpen] = useState(false)
  const menuRef = useRef<HTMLDivElement>(null)

  async function handleSignOut() {
    setOpen(false)
    await fetch("/api/logout", { method: "POST" })
    window.location.href = "/login"
  }

  useEffect(() => {
    void fetchCurrentUser().then(setUser)
  }, [])

  // Click-outside handling differs by variant:
  // - header: fixed overlay (already in JSX)
  // - footer: mousedown listener
  useEffect(() => {
    if (variant !== "footer" || !open) return
    function handleClick(e: MouseEvent) {
      if (menuRef.current && !menuRef.current.contains(e.target as Node)) {
        setOpen(false)
      }
    }
    document.addEventListener("mousedown", handleClick)
    return () => document.removeEventListener("mousedown", handleClick)
  }, [variant, open])

  if (!user || pathname === "/login") return null

  const roleLabel = ROLE_LABELS[user.role]
  const initials = user.username.slice(0, 2).toUpperCase()

  // ── Header variant ───────────────────────────────────────────
  if (variant === "header") {
    return (
      <div className="relative">
        <button
          type="button"
          aria-label={`Signed in as ${user.username}`}
          onClick={() => setOpen(!open)}
          className="flex max-w-56 items-center gap-2 rounded-lg border border-[var(--color-border)] bg-[var(--color-surface)] px-3 py-2 text-sm text-[var(--color-text-secondary)] transition-colors hover:bg-[var(--color-surface-raised)] hover:text-[var(--color-text-primary)]"
        >
          {user.avatarUrl ? (
            <img src={user.avatarUrl} alt={user.username} className="h-6 w-6 shrink-0 rounded-full object-cover" />
          ) : (
            <div className="flex h-6 w-6 shrink-0 items-center justify-center rounded-full bg-[var(--color-accent)] text-2xs font-bold text-[var(--color-accent-on)]">
              {initials}
            </div>
          )}
          <span className="min-w-0 truncate">{user.username}</span>
          <svg
            xmlns="http://www.w3.org/2000/svg"
            className="h-3 w-3 shrink-0 opacity-40"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="2"
            strokeLinecap="round"
            strokeLinejoin="round"
          >
            <path d="M6 9l6 6 6-6" />
          </svg>
        </button>

        {open && (
          <>
            <div className="fixed inset-0 z-40" onClick={() => setOpen(false)} />
            <div className="absolute right-0 top-12 z-50 w-56 rounded-xl border border-[var(--color-border)] bg-[var(--color-surface)] p-2 shadow-xl">
              <div className="border-b border-[var(--color-border)] px-3 py-2 mb-1">
                <p className="text-sm font-semibold text-[var(--color-text-primary)] truncate">
                  {user.username}
                </p>
                <p className="text-[11px] font-medium uppercase tracking-wider text-[var(--color-text-secondary)]">
                  {roleLabel}
                </p>
              </div>
              <button
                type="button"
                onClick={handleSignOut}
                className="flex w-full items-center rounded-lg px-3 py-2 text-sm text-[var(--color-severity-critical)] hover:bg-[var(--color-severity-critical-subtle)] transition-colors"
              >
                Sign out
              </button>
            </div>
          </>
        )}
      </div>
    )
  }

  // ── Footer variant ───────────────────────────────────────────
  return (
    <div className="relative" ref={menuRef}>
      <button
        type="button"
        aria-label={`Signed in as ${user.username}`}
        onClick={() => setOpen(!open)}
        title={collapsed ? `${user.username} · ${roleLabel}` : undefined}
        className={`w-full rounded-lg transition-colors hover:bg-[var(--color-surface-raised)] ${
          collapsed
            ? "flex justify-center p-1.5"
            : "flex items-center gap-2.5 px-2.5 py-2"
        }`}
      >
        {user.avatarUrl ? (
          <img src={user.avatarUrl} alt={user.username} className="h-7 w-7 shrink-0 rounded-full object-cover" />
        ) : (
          <div className="flex h-7 w-7 shrink-0 items-center justify-center rounded-full bg-[var(--color-accent)] text-[11px] font-bold text-[var(--color-accent-on)]">
            {initials}
          </div>
        )}
        {!collapsed && (
          <div className="min-w-0 flex-1 text-left">
            <p className="truncate text-[12.5px] font-medium text-[var(--color-text-primary)]">
              {user.username}
            </p>
            <p className="truncate text-2xs text-[var(--color-text-secondary)]">
              {user.email ?? roleLabel}
            </p>
          </div>
        )}
        {!collapsed && (
          <svg
            className="h-3 w-3 shrink-0 opacity-40"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth={2}
            strokeLinecap="round"
            strokeLinejoin="round"
          >
            <path d="M6 9l6 6 6-6" />
          </svg>
        )}
      </button>

      {open && (
        <div
          className={`absolute z-50 w-52 rounded-xl border border-[var(--color-border)] bg-[var(--color-surface)] p-1.5 shadow-xl ${
            collapsed ? "left-12 bottom-0" : "bottom-12 left-0"
          }`}
        >
          <div className="border-b border-[var(--color-border)] px-3 py-2 mb-1">
            <p className="text-sm font-semibold text-[var(--color-text-primary)] truncate">
              {user.username}
            </p>
            <p className="text-[11px] font-medium uppercase tracking-wider text-[var(--color-text-secondary)]">
              {roleLabel}
            </p>
          </div>
          <button
            type="button"
            onClick={handleSignOut}
            className="flex w-full items-center rounded-lg px-3 py-2 text-sm text-[var(--color-severity-critical)] hover:bg-[var(--color-severity-critical-subtle)] transition-colors"
          >
            Sign out
          </button>
        </div>
      )}
    </div>
  )
}
