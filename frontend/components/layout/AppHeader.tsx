"use client"

import { useEffect, useState } from "react"
import { usePathname } from "next/navigation"
import { useMobileSidebar } from "@/components/layout/MobileSidebarContext"
import { ThemeToggleButton } from "@/components/layout/ThemeToggleButton"
import { SearchModal } from "@/components/layout/SearchModal"
import { NotificationBell } from "@/components/layout/NotificationBell"
import { HeaderCTAs } from "@/components/layout/HeaderCTAs"
import Link from "next/link"
import { useConnectorCatalog, type Integration } from "@/lib/client/integrations-catalog-api"
import { getSourceConnection } from "@/lib/client/source-connections-api"
import { getRepo } from "@/lib/client/sources-api"
import { sourceDisplayName } from "@/lib/shared/sources-types"

/** Map of URL path segments to their display labels. */
const SEGMENT_LABELS: Record<string, string> = {
  settings: "Settings",
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
  iac: "IaC",
  code: "Code",
  secrets: "Secrets",
  containers: "Containers",
  dependencies: "Dependencies",
  posture: "Posture",
  sbom: "SBOM",
  components: "Components",
  risk: "Risky Packages",
  diff: "Compare",
  compliance: "Compliance",
  chains: "Attack Chains",
  findings: "Findings",
  images: "Images",
  inbox: "Inbox",
  notifications: "Notifications",
  operations: "Operations",
  policies: "Policies",
  insights: "Insights",
  reports: "Reports",
  repos: "Repositories",
  releases: "Releases",
  activity: "Activity",
  history: "History",
  triage: "Triage",
  "api-keys": "API Keys",
  sso: "SSO",
  audit: "Audit Log",
  "audit-log": "Audit Log",
  "sla-policies": "SLA Policies",
  rules: "Policies",
  integrations: "Integrations",
  "sla_policies": "SLA Policies",
}

/** Canonical labels for bundled compliance frameworks. Framework ids are dynamic
 *  route segments, so they'd otherwise be mangled by titleCase (iso27001 →
 *  "Iso27001"). Control ids under a framework keep their own casing (see below). */
const FRAMEWORK_LABELS: Record<string, string> = {
  soc2: "SOC 2",
  iso27001: "ISO 27001",
  "pci-dss": "PCI DSS",
}

/** Segments that should be hidden from breadcrumbs (intermediate route segments). */
const HIDDEN_SEGMENTS = new Set([])

/** Title-case a URL segment as a safety net when SEGMENT_LABELS doesn't cover it.
 *  e.g. "my-route" -> "My Route", "snake_case" -> "Snake Case". */
function titleCase(segment: string): string {
  return segment
    .split(/[-_\s]/)
    .filter(Boolean)
    .map((word) => word.charAt(0).toUpperCase() + word.slice(1).toLowerCase())
    .join(" ")
}

/** decodeURIComponent that never throws on a malformed segment (a bad URL must
 *  not crash the whole header). */
function safeDecode(segment: string): string {
  try {
    return decodeURIComponent(segment)
  } catch {
    return segment
  }
}

/**
 * Build breadcrumb items from the current pathname.
 *
 * Examples:
 *   "/"                      → [{ label: "Home" }]
 *   "/findings"              → [{ label: "Overview" }, { label: "Findings" }]
 *   "/members"               → [{ label: "Workspace" }, { label: "Members" }]
 *   "/sources"               → [{ label: "Inventory" }, { label: "Sources" }]
 *   "/integrations"          → [{ label: "Configure" }, { label: "Integrations" }]
 *   "/settings/account"      → [{ label: "Settings" }, { label: "Account" }]
 *   "/settings/iac-security" → [{ label: "Settings" }, { label: "Tools" }, { label: "IaC Security" }]
 * */
function buildBreadcrumbs(pathname: string, catalog: Integration[], sourceName?: string | null, repoName?: string | null): { label: string; href?: string }[] {
  if (pathname === "/") return [{ label: "Home" }]

  const segments = pathname.split("/").filter(Boolean)
  const crumbs: { label: string; href?: string }[] = []
  let prefix = ""

  for (let i = 0; i < segments.length; i++) {
    const segment = segments[i]
    prefix += "/" + segment

    // Top-level routes that live under a sidebar group: prefix with the
    // group label so the breadcrumb mirrors the navigation hierarchy
    // (e.g. /members → "Workspace > Members"). Group labels are synthetic — no href.
    // Home ("/") stays bare (handled by the early return at the top of this fn).
    if (i === 0) {
      const OVERVIEW: Record<string, string> = {
        inbox: "Inbox", findings: "Findings", insights: "Insights",
      }
      const WORKSPACE: Record<string, string> = {
        members: "Members", roles: "Roles", teams: "Teams",
      }
      const INVENTORY: Record<string, string> = {
        sources: "Sources", sbom: "SBOM", chains: "Chains",
      }
      const REPORTING: Record<string, string> = {
        compliance: "Compliance", reports: "Reports",
      }
      const CONFIGURE: Record<string, string> = {
        // /rules is the actual route — the sidebar surfaces it as "Policies",
        // so the breadcrumb matches.
        policies: "Policies", rules: "Policies",
        integrations: "Integrations", notifications: "Notifications",
      }
      if (OVERVIEW[segment]) {
        crumbs.push({ label: "Overview" })
        crumbs.push({ label: OVERVIEW[segment], href: prefix })
        continue
      }
      if (WORKSPACE[segment]) {
        crumbs.push({ label: "Workspace" })
        crumbs.push({ label: WORKSPACE[segment], href: prefix })
        continue
      }
      if (INVENTORY[segment]) {
        crumbs.push({ label: "Inventory" })
        crumbs.push({ label: INVENTORY[segment], href: prefix })
        continue
      }
      if (REPORTING[segment]) {
        crumbs.push({ label: "Reporting" })
        crumbs.push({ label: REPORTING[segment], href: prefix })
        continue
      }
      if (CONFIGURE[segment]) {
        crumbs.push({ label: "Configure" })
        crumbs.push({ label: CONFIGURE[segment], href: prefix })
        continue
      }
    }

    // Settings sub-categories: Tools, System, Workspace are synthetic groupings (no href).
    if (i > 0 && segments[i - 1] === "settings") {
      const TOOLS: Record<string, string> = {
        "iac-security": "IaC Security",
      }
      const SYSTEM: Record<string, string> = {
        runners: "Runners", integrations: "Integrations", license: "License",
      }

      if (TOOLS[segment]) {
        crumbs.push({ label: "Tools" })
        crumbs.push({ label: TOOLS[segment], href: prefix })
        continue
      }
      if (SYSTEM[segment]) {
        crumbs.push({ label: "System" })
        crumbs.push({ label: SYSTEM[segment], href: prefix })
        continue
      }
      const WORKSPACE: Record<string, string> = {
        organisations: "Organisations", users: "Members", roles: "Roles",
      }
      if (WORKSPACE[segment]) {
        crumbs.push({ label: "Workspace" })
        crumbs.push({ label: WORKSPACE[segment], href: prefix })
        continue
      }
    }

    // Integration sub-routes: resolve slug → human name (e.g. github-action → GitHub Action)
    if (i > 0 && segments[i - 1] === "integrations") {
      const integration = catalog.find(x => x.slug === segment)
      if (integration) {
        crumbs.push({ label: integration.name, href: prefix })
        continue
      }
    }

    // Source detail sub-routes: the segment after "sources" is an opaque ID — use the
    // fetched source name when available, falling back to "Source" while loading.
    if (i > 0 && segments[i - 1] === "sources" && !(segment in SEGMENT_LABELS)) {
      crumbs.push({ label: sourceName ?? "Source", href: prefix })
      continue
    }

    // SBOM repo detail: the segment after "sbom" is an opaque owner/name id
    // (the static "components"/"diff" tabs are caught by SEGMENT_LABELS above).
    if (i > 0 && segments[i - 1] === "sbom" && !(segment in SEGMENT_LABELS)) {
      // Prefer the resolved repo name; fall back to the raw id while it loads.
      crumbs.push({ label: repoName || safeDecode(segment), href: prefix })
      continue
    }

    // Compliance framework + control segments are domain identifiers — preserve
    // their canonical casing rather than mangling them through titleCase
    // (iso27001 → "Iso27001", CC6.1 → "Cc6.1"). There is no standalone framework
    // route (only /compliance and /compliance/<fw>/<control> exist), so the
    // framework crumb is label-only — no href, to avoid a 404 on click.
    if (i > 0 && segments[i - 1] === "compliance") {
      crumbs.push({ label: FRAMEWORK_LABELS[segment] ?? titleCase(segment) })
      continue
    }
    if (i > 1 && segments[i - 2] === "compliance") {
      crumbs.push({ label: safeDecode(segment), href: prefix })
      continue
    }

    const label = SEGMENT_LABELS[segment] ?? titleCase(segment)
    crumbs.push({ label, href: prefix })
  }

  // Current page is the last crumb — drop its href so it renders as plain text.
  if (crumbs.length > 0 && crumbs[crumbs.length - 1].href !== undefined) {
    crumbs[crumbs.length - 1] = { label: crumbs[crumbs.length - 1].label }
  }

  if (crumbs.length === 0) return [{ label: "Home" }]

  return crumbs
}

export function AppHeader({
  open,
  setSearchOpen,
}: {
  open: boolean
  setSearchOpen: (value: boolean) => void
}) {
  const pathname = usePathname()
  const { setOpen } = useMobileSidebar()
  const { catalog } = useConnectorCatalog()
  const [sourceName, setSourceName] = useState<string | null>(null)
  const [repoName, setRepoName] = useState<string | null>(null)

  // Resolve the opaque source ID segment to a human name for the breadcrumb.
  // Runs only when the path contains /sources/<id>.
  useEffect(() => {
    const segments = pathname.split("/").filter(Boolean)
    const idx = segments.indexOf("sources")
    const sourceId = idx >= 0 && idx + 1 < segments.length && !(segments[idx + 1] in SEGMENT_LABELS)
      ? segments[idx + 1]
      : null
    if (!sourceId) {
      setSourceName(null)
      return
    }
    let cancelled = false
    getSourceConnection(sourceId)
      .then((r) => { if (!cancelled && r.ok) setSourceName(sourceDisplayName(r.data.connection)) })
      .catch(() => {})
    return () => { cancelled = true }
  }, [pathname])

  // Same, for the SBOM repo detail route /sbom/<asset-id>.
  useEffect(() => {
    const segments = pathname.split("/").filter(Boolean)
    const idx = segments.indexOf("sbom")
    const repoId = idx >= 0 && idx + 1 < segments.length && !(segments[idx + 1] in SEGMENT_LABELS)
      ? segments[idx + 1]
      : null
    if (!repoId) {
      setRepoName(null)
      return
    }
    let cancelled = false
    getRepo(repoId)
      .then((r) => { if (!cancelled && r) setRepoName(r.display_name || [r.org, r.repo].filter(Boolean).join("/") || null) })
      .catch(() => {})
    return () => { cancelled = true }
  }, [pathname])

  const crumbs = buildBreadcrumbs(pathname, catalog, sourceName, repoName)

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
    <header className="flex h-14 items-center justify-between border-b border-[var(--color-border)] bg-[var(--color-surface)] px-6">
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
        <nav aria-label="Breadcrumb" className="flex items-center gap-1.5 font-mono text-xs uppercase tracking-[0.06em] min-w-0">
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
                  aria-hidden="true"
                >
                  <path d="M9 18l6-6-6-6" />
                </svg>
              )}
              {crumb.href ? (
                <Link
                  href={crumb.href}
                  className="truncate rounded-sm text-[var(--color-text-secondary)] transition-colors hover:text-[var(--color-text-primary)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)] focus-visible:ring-offset-1 focus-visible:ring-offset-[var(--color-surface)]"
                >
                  {crumb.label}
                </Link>
              ) : (
                <span
                  aria-current={i === crumbs.length - 1 ? "page" : undefined}
                  className="truncate font-medium text-[var(--color-text-primary)]"
                >
                  {crumb.label}
                </span>
              )}
            </span>
          ))}
        </nav>
      </div>

      {/* Right: community CTAs + utility icons */}
      <div className="flex items-center gap-2">
        <HeaderCTAs />
        <div className="mx-1 h-5 w-px bg-[var(--color-border)]" aria-hidden="true" />
        <NotificationBell />
        <Link
          href="/settings"
          aria-label="Settings"
          onClick={(e) => {
            if (pathname.startsWith("/settings")) {
              e.preventDefault()
              const container = document.querySelector<HTMLElement>("[data-app-scroll]")
              if (container) container.scrollTo({ top: 0, behavior: "smooth" })
              else window.scrollTo({ top: 0, behavior: "smooth" })
              if (window.location.hash || window.location.pathname !== "/settings") {
                window.history.replaceState(null, "", "/settings")
              }
            }
          }}
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
