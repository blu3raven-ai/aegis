"use client"

import { useEffect } from "react"
import { usePathname } from "next/navigation"
import { useMobileSidebar } from "@/components/layout/MobileSidebarContext"
import { ThemeToggleButton } from "@/components/layout/ThemeToggleButton"
import { SearchModal } from "@/components/layout/SearchModal"
import { NotificationBell } from "@/components/layout/NotificationBell"
import { HeaderCTAs } from "@/components/layout/HeaderCTAs"
import Link from "next/link"

/** Map of URL path segments to their display labels. */
const SEGMENT_LABELS: Record<string, string> = {
  dependencies: "Dependency Scanning (SCA)",
  containers: "Container Scanning",
  secrets: "Secret Scanning",
  code: "Code Scanning (SAST)",
  iac: "IaC Security",
  settings: "Settings",
  dashboard: "Dashboard",
  account: "Account",
  general: "General",
  sources: "Sources",
  "code-repositories": "Git Repository",
  "container-registry": "Container Registry",
  "cloud-infrastructure": "Cloud Infrastructure",
  organisations: "Organisations",
  license: "License",
  roles: "Roles",
  runners: "Runners",
  users: "Users",
  "iac-security": "IaC Security",
  help: "Help & Support",
  notifications: "Notifications",
  operations: "Operations",
  sbom: "SBOM Explorer",
}

/** Segments that should be hidden from breadcrumbs (intermediate route segments). */
const HIDDEN_SEGMENTS = new Set([])

/**
 * Build breadcrumb items from the current pathname.
 *
 * Examples:
 *   "/"                    → [{ label: "Home" }]
 *   "/dependencies/dashboard" → [{ label: "Tools" }, { label: "Dependencies" }]
 *   "/code/dashboard/org"    → [{ label: "Tools" }, { label: "Code" }, { label: "org" }]
 *   "/settings/account"      → [{ label: "Settings" }, { label: "Account" }]
 *   "/settings/dependencies" → [{ label: "Settings" }, { label: "Dependencies" }]
 * */
function buildBreadcrumbs(pathname: string): { label: string }[] {
  if (pathname === "/") return [{ label: "Home" }]
  if (pathname === "/operations") return [{ label: "Operations" }, { label: "Integrations" }]

  const segments = pathname.split("/").filter(Boolean)
  const crumbs: { label: string }[] = []

  for (let i = 0; i < segments.length; i++) {
    const segment = segments[i]

    // Special handling for tool paths:
    // - For tool segments (dependencies/secrets/code/etc): show "Tools"
    // - For dashboard following a tool: show the label from SEGMENT_LABELS (e.g. "SCA")
    if (segment === "dashboard" &&
        i > 0 &&
        ["dependencies", "containers", "secrets", "code", "iac"].includes(segments[i-1])) {
      // Show the label for the tool segment (e.g. "SCA") instead of "Dashboard"
      const toolSegment = segments[i-1]
      const label = SEGMENT_LABELS[toolSegment] ?? toolSegment
      crumbs.push({ label })
      continue
    }

    // Special handling for tool dashboard routes (/dependencies/dashboard, /secrets/dashboard, etc.)
    if (["dependencies", "containers", "secrets", "code", "iac"].includes(segment) && (i === 0 || segments[i - 1] !== "settings")) {
      crumbs.push({ label: "Tools" })
      continue
    }

    // Settings sub-categories: Tools and System
    if (i > 0 && segments[i - 1] === "settings") {
      const TOOLS: Record<string, string> = {
        dependencies: "Dependencies", containers: "Containers", code: "Code",
        secrets: "Secrets", "iac-security": "IaC Security",
      }
      const SYSTEM: Record<string, string> = {
        runners: "Runners", license: "License",
      }

      if (TOOLS[segment]) {
        crumbs.push({ label: "Tools" })
        crumbs.push({ label: TOOLS[segment] })
        continue
      }
      if (SYSTEM[segment]) {
        crumbs.push({ label: "System" })
        crumbs.push({ label: SYSTEM[segment] })
        continue
      }
      const WORKSPACE: Record<string, string> = {
        organisations: "Organisations", users: "Members", roles: "Roles",
      }
      if (WORKSPACE[segment]) {
        crumbs.push({ label: "Workspace" })
        crumbs.push({ label: WORKSPACE[segment] })
        continue
      }
    }

    const label = SEGMENT_LABELS[segment] ?? segment
    crumbs.push({ label })
  }

  // Fallback: if all segments were hidden, show "Home"
  if (crumbs.length === 0) return [{ label: "Home" }]

  return crumbs
}

export function AppHeader({ open, setSearchOpen }: { open: boolean; setSearchOpen: (value: boolean) => void }) {
  const pathname = usePathname()
  const { setOpen } = useMobileSidebar()
  const crumbs = buildBreadcrumbs(pathname)

  // Global ⌘K listener to open/close search modal
  useEffect(() => {
    function handleKeyDown(e: KeyboardEvent) {
      if ((e.metaKey || e.ctrlKey) && e.key === "k") {
        e.preventDefault()
        setSearchOpen(!open)
      }
    }
    window.addEventListener("keydown", handleKeyDown)
    return () => window.removeEventListener("keydown", handleKeyDown)
  }, [open, setSearchOpen])

  return (
    <header className="sticky top-0 z-30 flex h-14 items-center justify-between border-b border-[var(--color-border)] bg-[var(--color-surface)] px-4">
      {/* Left: hamburger (mobile) + breadcrumbs */}
      <div className="flex items-center gap-2 min-w-0">
        {/* Mobile hamburger */}
        <button
          type="button"
          aria-label="Open menu"
          onClick={() => setOpen(true)}
          className="rounded-md p-2 text-[var(--color-text-secondary)] transition-colors hover:bg-[var(--color-surface-raised)] hover:text-[var(--color-text-primary)] md:hidden"
        >
          <svg
            xmlns="http://www.w3.org/2000/svg"
            className="h-5 w-5"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth={2}
            strokeLinecap="round"
            strokeLinejoin="round"
          >
            <line x1="4" y1="6" x2="20" y2="6" />
            <line x1="4" y1="12" x2="20" y2="12" />
            <line x1="4" y1="18" x2="20" y2="18" />
          </svg>
        </button>

        {/* Breadcrumbs */}
        <nav aria-label="Breadcrumb" className="flex items-center gap-1.5 text-sm min-w-0">
          {crumbs.map((crumb, i) => (
            <span key={crumb.label} className="flex items-center gap-1.5 min-w-0">
              {i > 0 && (
                <svg
                  xmlns="http://www.w3.org/2000/svg"
                  className="h-3.5 w-3.5 shrink-0 text-[var(--color-text-secondary)] opacity-50"
                  viewBox="0 0 24 24"
                  fill="none"
                  stroke="currentColor"
                  strokeWidth={2}
                  strokeLinecap="round"
                  strokeLinejoin="round"
                >
                  <path d="M9 18l6-6-6-6" />
                </svg>
              )}
              <span
                className={`truncate ${
                  i === crumbs.length - 1
                    ? "font-medium text-[var(--color-text-primary)]"
                    : "text-[var(--color-text-secondary)]"
                }`}
              >
                {crumb.label}
              </span>
            </span>
          ))}
        </nav>
      </div>

      {/* Right: community CTAs + utility icons */}
      <div className="flex items-center gap-2">
        <HeaderCTAs />
        <div className="h-4 w-px bg-[var(--color-border)]" aria-hidden="true" />
        <NotificationBell />
        <Link
          href="/settings/account"
          aria-label="Settings"
          className="rounded-lg p-2 text-[var(--color-text-secondary)] transition-colors hover:bg-[var(--color-surface-raised)] hover:text-[var(--color-text-primary)]"
        >
          <svg className="h-5 w-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.5} strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
            <path d="M9.594 3.94c.09-.542.56-.94 1.11-.94h2.593c.55 0 1.02.398 1.11.94l.213 1.281c.063.374.313.686.645.87.074.04.147.083.22.127.325.196.72.257 1.075.124l1.217-.456a1.125 1.125 0 0 1 1.37.49l1.296 2.247a1.125 1.125 0 0 1-.26 1.431l-1.003.827c-.293.241-.438.613-.43.992a7.723 7.723 0 0 1 0 .255c-.008.378.137.75.43.991l1.004.827c.424.35.534.955.26 1.43l-1.298 2.247a1.125 1.125 0 0 1-1.369.491l-1.217-.456c-.355-.133-.75-.072-1.076.124a6.47 6.47 0 0 1-.22.128c-.331.183-.581.495-.644.869l-.213 1.281c-.09.543-.56.94-1.11.94h-2.594c-.55 0-1.019-.398-1.11-.94l-.213-1.281c-.062-.374-.312-.686-.644-.87a6.52 6.52 0 0 1-.22-.127c-.325-.196-.72-.257-1.076-.124l-1.217.456a1.125 1.125 0 0 1-1.369-.49l-1.297-2.247a1.125 1.125 0 0 1 .26-1.431l1.004-.827c.292-.24.437-.613.43-.991a6.932 6.932 0 0 1 0-.255c.007-.38-.138-.751-.43-.992l-1.004-.827a1.125 1.125 0 0 1-.26-1.43l1.297-2.247a1.125 1.125 0 0 1 1.37-.491l1.216.456c.356.133.751.072 1.076-.124.072-.044.146-.086.22-.128.332-.183.582-.495.644-.869l.214-1.28Z" />
            <path d="M15 12a3 3 0 1 1-6 0 3 3 0 0 1 6 0Z" />
          </svg>
        </Link>
        <ThemeToggleButton />
      </div>

      {/* Search Modal */}
      <SearchModal open={open} onClose={() => setSearchOpen(false)} />
    </header>
  )
}
