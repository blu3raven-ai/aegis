"use client"

import Link from "next/link"
import { useEffect, type ReactNode, type MouseEvent } from "react"
import { useActiveSection } from "./useActiveSection"

// Scrolls the settings content column (not main) to bring a target section
// into view. The content column is the only scrolling element on the settings
// page — main itself is overflow-hidden so the PageHeader and nav stay pinned.
function scrollMainTo(id: string, behavior: ScrollBehavior = "smooth") {
  if (typeof window === "undefined") return
  const container = document.querySelector("[data-settings-content]") as HTMLElement | null
  const target = document.getElementById(id)
  if (!container || !target) return
  const containerTop = container.getBoundingClientRect().top
  const targetTop = target.getBoundingClientRect().top
  const margin = parseInt(getComputedStyle(target).scrollMarginTop || "16", 10) || 16
  container.scrollTo({
    top: Math.max(0, container.scrollTop + (targetTop - containerTop) - margin),
    behavior,
  })
}

interface NavItem {
  id: string
  href: string
  label: string
  icon: ReactNode
}

// Outline icons paired one-to-one with the nav items. They're decorative — the
// label remains the accessible name on each Link.
const ICONS = {
  user: (
    <svg
      aria-hidden="true"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={1.8}
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <circle cx="12" cy="8" r="4" />
      <path d="M4 21v-1a6 6 0 0 1 6-6h4a6 6 0 0 1 6 6v1" />
    </svg>
  ),
  bell: (
    <svg
      aria-hidden="true"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={1.8}
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <path d="M14.857 17.082a23.848 23.848 0 0 0 5.454-1.31A8.967 8.967 0 0 1 18 9.75V9A6 6 0 0 0 6 9v.75a8.967 8.967 0 0 1-2.312 6.022c1.733.64 3.56 1.085 5.455 1.31m5.714 0a24.255 24.255 0 0 1-5.714 0m5.714 0a3 3 0 1 1-5.714 0" />
    </svg>
  ),
  shield: (
    <svg
      aria-hidden="true"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={1.8}
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
    </svg>
  ),
  key: (
    <svg
      aria-hidden="true"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={1.8}
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <path d="M15.75 5.25a3 3 0 0 1 3 3m3 0a6 6 0 0 1-7.029 5.912c-.563-.097-1.159.026-1.563.43L10.5 17.25H8.25v2.25H6v2.25H2.25v-2.818c0-.597.237-1.17.659-1.591l6.499-6.499c.404-.404.527-1 .43-1.563A6 6 0 1 1 21.75 8.25Z" />
    </svg>
  ),
  building: (
    <svg
      aria-hidden="true"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={1.8}
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <path d="M3 21h18M3 7l9-4 9 4M5 21V11m14 10V11M9 21v-7m6 7v-7" />
    </svg>
  ),
  users: (
    <svg
      aria-hidden="true"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={1.8}
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <path d="M16 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2" />
      <circle cx="8.5" cy="7" r="4" />
      <path d="M20 8v6m-3-3h6" />
    </svg>
  ),
  shieldCheck: (
    <svg
      aria-hidden="true"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={1.8}
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
      <path d="m9 12 2 2 4-4" />
    </svg>
  ),
  team: (
    <svg
      aria-hidden="true"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={1.8}
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <path d="M17 21v-2a4 4 0 0 0-3-3.87" />
      <path d="M7 21v-2a4 4 0 0 1 3-3.87" />
      <circle cx="12" cy="7" r="4" />
      <path d="M5 11h.01M19 11h.01" />
    </svg>
  ),
  lock: (
    <svg
      aria-hidden="true"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={1.8}
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <path d="M16.5 10.5V6.75a4.5 4.5 0 1 0-9 0v3.75m-.75 11.25h10.5a2.25 2.25 0 0 0 2.25-2.25v-6.75a2.25 2.25 0 0 0-2.25-2.25H6.75a2.25 2.25 0 0 0-2.25 2.25v6.75a2.25 2.25 0 0 0 2.25 2.25Z" />
    </svg>
  ),
  scroll: (
    <svg
      aria-hidden="true"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={1.8}
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <path d="M9 5H7a2 2 0 0 0-2 2v12a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V7a2 2 0 0 0-2-2h-2M9 5a2 2 0 0 0 2 2h2a2 2 0 0 0 2-2M9 5a2 2 0 0 1 2-2h2a2 2 0 0 1 2 2m-6 9 2 2 4-4" />
    </svg>
  ),
  plug: (
    <svg
      aria-hidden="true"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={1.8}
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <path d="M9 2v6M15 2v6M5 8h14v6a4 4 0 0 1-4 4h-1v4h-4v-4H9a4 4 0 0 1-4-4V8z" />
    </svg>
  ),
  runner: (
    <svg
      aria-hidden="true"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={1.8}
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <rect x="3" y="4" width="18" height="12" rx="2" />
      <path d="M8 20h8M12 16v4" />
      <circle cx="8" cy="10" r="1" />
      <circle cx="12" cy="10" r="1" />
    </svg>
  ),
  badge: (
    <svg
      aria-hidden="true"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={1.8}
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
      <circle cx="12" cy="10" r="2.5" />
    </svg>
  ),
  sparkles: (
    <svg
      aria-hidden="true"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={1.8}
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <path d="M9.813 15.904 9 18.75l-.813-2.846a4.5 4.5 0 0 0-3.09-3.09L2.25 12l2.846-.813a4.5 4.5 0 0 0 3.09-3.09L9 5.25l.813 2.846a4.5 4.5 0 0 0 3.09 3.09L15.75 12l-2.846.813a4.5 4.5 0 0 0-3.09 3.09ZM18.259 8.715 18 9.75l-.259-1.035a3.375 3.375 0 0 0-2.455-2.456L14.25 6l1.036-.259a3.375 3.375 0 0 0 2.455-2.456L18 2.25l.259 1.035a3.375 3.375 0 0 0 2.456 2.456L21.75 6l-1.035.259a3.375 3.375 0 0 0-2.456 2.456ZM16.894 20.567 16.5 21.75l-.394-1.183a2.25 2.25 0 0 0-1.423-1.423L13.5 18.75l1.183-.394a2.25 2.25 0 0 0 1.423-1.423l.394-1.183.394 1.183a2.25 2.25 0 0 0 1.423 1.423l1.183.394-1.183.394a2.25 2.25 0 0 0-1.423 1.423Z" />
    </svg>
  ),
}

interface NavGroupSpec {
  label: string
  items: NavItem[]
}

// Two top-level buckets: everything scoped to the signed-in user under
// "Personal", everything that is org-admin under "Organization". API tokens are
// personal access tokens, so they live in Personal — not the org cluster.
const NAV_GROUPS: NavGroupSpec[] = [
  {
    label: "Personal",
    items: [
      { id: "profile", href: "#profile", label: "Profile", icon: ICONS.user },
      { id: "notifications", href: "#notifications", label: "Notifications", icon: ICONS.bell },
      { id: "security", href: "#security", label: "Security & Sessions", icon: ICONS.shield },
      { id: "api-keys", href: "#api-keys", label: "API Tokens", icon: ICONS.key },
    ],
  },
  {
    label: "Organization",
    items: [
      { id: "general", href: "#general", label: "General", icon: ICONS.building },
      { id: "sso", href: "#sso", label: "SSO / SAML", icon: ICONS.lock },
      { id: "audit", href: "#audit", label: "Audit Log", icon: ICONS.scroll },
      { id: "runners", href: "#runners", label: "Runners", icon: ICONS.runner },
      { id: "argus", href: "#argus", label: "Argus", icon: ICONS.sparkles },
      { id: "license", href: "#license", label: "License", icon: ICONS.badge },
    ],
  },
]

const ALL_IDS = NAV_GROUPS.flatMap((g) => g.items.map((i) => i.id)) as readonly string[]

export function SettingsInPageNav() {
  const activeId = useActiveSection(ALL_IDS, "-16px 0px -65% 0px", "[data-settings-content]")

  // Honour the URL hash on initial mount + when the user navigates back/forward
  // — main needs to be scrolled manually because the document is overflow-locked.
  useEffect(() => {
    const hash = window.location.hash.slice(1)
    if (hash) {
      // Defer one frame so the layout has settled before we measure.
      requestAnimationFrame(() => scrollMainTo(hash, "auto"))
    }
    const onPopState = () => {
      const next = window.location.hash.slice(1)
      if (next) scrollMainTo(next, "smooth")
    }
    window.addEventListener("popstate", onPopState)
    return () => window.removeEventListener("popstate", onPopState)
  }, [])

  return (
    <nav
      aria-label="Settings sections"
      className="hidden w-[220px] shrink-0 overflow-y-auto border-r border-[var(--color-border)] pl-6 pr-2 py-6 md:flex md:flex-col"
    >
      {NAV_GROUPS.map((group, index) => (
        <NavGroup key={group.label} {...group} activeId={activeId} withDivider={index > 0} />
      ))}
    </nav>
  )
}

function NavGroup({
  label,
  items,
  activeId,
  withDivider,
}: NavGroupSpec & { activeId: string | null; withDivider?: boolean }) {
  return (
    <div
      className={
        withDivider
          ? "mt-5 border-t border-[var(--color-border)] pt-5"
          : "mb-1"
      }
    >
      <div className="px-3 pb-1.5 text-2xs font-semibold uppercase tracking-[0.14em] text-[var(--color-text-tertiary)]">
        {label}
      </div>
      <div className="flex flex-col gap-0.5">
        {items.map((item) => {
          const active = activeId === item.id
          return (
            <Link
              key={item.id}
              href={item.href}
              aria-current={active ? "page" : undefined}
              onClick={(e: MouseEvent<HTMLAnchorElement>) => {
                e.preventDefault()
                window.history.pushState(null, "", item.href)
                scrollMainTo(item.id, "smooth")
              }}
              className={`flex items-center gap-2.5 rounded-md px-3 py-2 text-sm transition-colors ${
                active
                  ? "bg-[var(--color-nav-active)] font-semibold text-[var(--color-accent)]"
                  : "text-[var(--color-text-secondary)] hover:bg-[var(--color-surface-raised)] hover:text-[var(--color-text-primary)]"
              }`}
            >
              <span
                className={`h-3.5 w-3.5 shrink-0 ${
                  active ? "text-[var(--color-accent)]" : "text-[var(--color-text-tertiary)]"
                }`}
              >
                {item.icon}
              </span>
              {item.label}
            </Link>
          )
        })}
      </div>
    </div>
  )
}
