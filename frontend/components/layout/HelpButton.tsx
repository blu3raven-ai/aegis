"use client"

import { useEffect, useRef, useState } from "react"
import Link from "next/link"
import { Button } from "@/components/ui/Button"
import { cn } from "@/lib/shared/utils"
import { getSetupChecklist } from "@/lib/client/setup-checklist"

// "?" icon in the AppHeader, top-right between the notifications bell and
// the avatar. Standard B2B convention (Snyk, Datadog, Linear, GitHub).
// Click opens a dropdown of help affordances — docs, keyboard shortcuts,
// status — plus a "Resume setup" entry that deep-links to the inline
// checklist card on the home dashboard via /#setup.

interface MenuItemLink {
  kind: "link"
  href: string
  icon: React.ReactNode
  label: string
  external?: boolean
}

type MenuItem = MenuItemLink | { kind: "divider" }

export function HelpButton() {
  const [open, setOpen] = useState(false)
  // Setup checklist completeness drives whether to show the "Resume setup"
  // entry — if 100% complete, the inline card hides itself, so the deep
  // link would land users on the home page with nothing to scroll to.
  const [setupIncomplete, setSetupIncomplete] = useState(false)
  const wrapperRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    let cancelled = false
    function load() {
      void getSetupChecklist()
        .then((tasks) => {
          if (cancelled) return
          const remaining = tasks.filter((t) => !t.done).length
          setSetupIncomplete(remaining > 0)
        })
        .catch(() => {
          if (!cancelled) setSetupIncomplete(false)
        })
    }
    load()
    function onFocus() { load() }
    window.addEventListener("focus", onFocus)
    return () => { cancelled = true; window.removeEventListener("focus", onFocus) }
  }, [])

  // Click-outside + Esc close
  useEffect(() => {
    if (!open) return
    function onDocClick(e: MouseEvent) {
      if (!wrapperRef.current?.contains(e.target as Node)) setOpen(false)
    }
    function onKey(e: KeyboardEvent) {
      if (e.key === "Escape") setOpen(false)
    }
    document.addEventListener("mousedown", onDocClick)
    document.addEventListener("keydown", onKey)
    return () => {
      document.removeEventListener("mousedown", onDocClick)
      document.removeEventListener("keydown", onKey)
    }
  }, [open])

  const items: MenuItem[] = [
    ...(setupIncomplete
      ? [
          {
            kind: "link" as const,
            href: "/#setup",
            icon: <ChecklistIcon />,
            label: "Resume setup",
          },
          { kind: "divider" as const },
        ]
      : []),
    {
      kind: "link",
      href: "https://docs.aegis.security",
      icon: <BookIcon />,
      label: "Documentation",
      external: true,
    },
    {
      kind: "link",
      href: "/keyboard-shortcuts",
      icon: <KeyboardIcon />,
      label: "Keyboard shortcuts",
    },
    { kind: "divider" },
    {
      kind: "link",
      href: "https://status.aegis.security",
      icon: <StatusIcon />,
      label: "Status",
      external: true,
    },
    {
      kind: "link",
      href: "mailto:support@aegis.security",
      icon: <SupportIcon />,
      label: "Contact support",
    },
  ]

  return (
    <div ref={wrapperRef} className="relative">
      <Button
        variant="ghost"
        size="sm"
        iconOnly
        onClick={() => setOpen((o) => !o)}
        aria-haspopup="menu"
        aria-expanded={open}
        aria-label="Help and resources"
      >
        <svg
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          strokeWidth={1.5}
          strokeLinecap="round"
          strokeLinejoin="round"
          aria-hidden="true"
        >
          <circle cx="12" cy="12" r="9" />
          <path d="M9.75 9a2.25 2.25 0 1 1 3.43 1.91c-.6.42-1.18.92-1.18 1.84v.5" />
          <path d="M12 17h.01" />
        </svg>
      </Button>

      {open && (
        <div
          role="menu"
          aria-label="Help menu"
          className="absolute right-0 top-full z-50 mt-1 w-60 overflow-hidden rounded-lg border border-[var(--color-border)] bg-[var(--color-surface)] py-1 shadow-[0_18px_40px_rgba(15,23,42,0.18)]"
        >
          {items.map((item, idx) => {
            if (item.kind === "divider") {
              return <div key={`div-${idx}`} className="my-1 h-px bg-[var(--color-border-divider)]" />
            }
            const inner = (
              <>
                <span aria-hidden="true" className="h-3.5 w-3.5 shrink-0 text-[var(--color-text-tertiary)]">
                  {item.icon}
                </span>
                <span className="flex-1">{item.label}</span>
                {item.external && <ExternalIcon />}
              </>
            )
            const rowClass = cn(
              "flex w-full items-center gap-2 px-3 py-1.5 text-left text-xs text-[var(--color-text-primary)] transition-colors hover:bg-[var(--color-bg-hover)] focus-visible:outline-none focus-visible:bg-[var(--color-bg-hover)]",
            )
            return item.external ? (
              <a
                key={item.label}
                href={item.href}
                target="_blank"
                rel="noreferrer noopener"
                role="menuitem"
                className={rowClass}
                onClick={() => setOpen(false)}
              >
                {inner}
              </a>
            ) : (
              <Link
                key={item.label}
                href={item.href}
                role="menuitem"
                className={rowClass}
                onClick={() => setOpen(false)}
              >
                {inner}
              </Link>
            )
          })}
        </div>
      )}
    </div>
  )
}

function ChecklistIcon() {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.5} strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d="M9 6h12M9 12h12M9 18h12M4.5 6l1 1 2-2M4.5 12l1 1 2-2M4.5 18l1 1 2-2" />
    </svg>
  )
}
function BookIcon() {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.5} strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d="M4 4.5A2.5 2.5 0 0 1 6.5 2H20v17H6.5A2.5 2.5 0 0 1 4 16.5z" />
      <path d="M20 22H6.5a2.5 2.5 0 0 1 0-5H20" />
    </svg>
  )
}
function KeyboardIcon() {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.5} strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <rect x="2" y="6" width="20" height="12" rx="2" />
      <path d="M6 10h.01M10 10h.01M14 10h.01M18 10h.01M6 14h.01M10 14h.01M14 14h.01M18 14h.01M8 14h8" />
    </svg>
  )
}
function StatusIcon() {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.5} strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <circle cx="12" cy="12" r="9" />
      <path d="M12 7v5l3 2" />
    </svg>
  )
}
function SupportIcon() {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.5} strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d="M21 11.5a8.5 8.5 0 1 1-17 0V11a8 8 0 0 1 16 0v.5z" />
      <path d="M3 11h3v6H3zm15 0h3v6h-3z" />
    </svg>
  )
}
function ExternalIcon() {
  return (
    <svg
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={1.5}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      className="h-3 w-3 shrink-0 text-[var(--color-text-tertiary)]"
    >
      <path d="M14 5h5v5M19 5l-9 9M5 9v10h10" />
    </svg>
  )
}
