"use client"

import Link from "next/link"
import { useMountedPathname } from "@/lib/client/use-mounted-pathname"
import { Tooltip } from "@/components/layout/Tooltip"
import { UserMenuButton } from "@/components/layout/UserMenuButton"
import { BrandLogo } from "@/components/layout/BrandLogo"
import { useBranding } from "@/lib/client/branding/client"
import { useLicense } from "@/lib/client/license/client"
import { TIER_LABELS } from "@/lib/shared/license/types"
import type { Tier } from "@/lib/shared/license/types"

const ICON_SEARCH = "M21 21l-5.197-5.197m0 0A7.5 7.5 0 1 0 5.196 5.196a7.5 7.5 0 0 0 10.607 10.607Z"

export interface SidebarContentProps {
  dependenciesEnabled: boolean
  container_scanningEnabled: boolean
  secretsEnabled: boolean
  code_scanningEnabled: boolean
  iacEnabled: boolean
  /** Aggregate navigation badge counts. Each is optional — undefined hides the badge for that item. */
  navCounts?: { inbox?: number; findings?: number }
  orgCount?: number
  collapsed: boolean
  /** Optional callback invoked when a navigation link is clicked (used by mobile drawer to close) */
  onNavigate?: () => void
  /** Optional list of tool labels currently running a backend scan (e.g. ["SCA", "Secrets"]) */
  scanningTools?: string[]
  /** Search modal state — renders a search trigger above Home when provided */
  searchOpen?: boolean
  onSearchOpen?: (open: boolean) => void
  /** Dynamic role-permission mapping from backend */
  policy?: any
}

const ICON_HOME =
  "M2.25 12l8.954-8.955c.44-.439 1.152-.439 1.591 0L21.75 12M4.5 9.75v10.125c0 .621.504 1.125 1.125 1.125H9.75v-4.875c0-.621.504-1.125 1.125-1.125h2.25c.621 0 1.125.504 1.125 1.125V21h4.125c.621 0 1.125-.504 1.125-1.125V9.75M8.25 21h8.25"


const ICON_FINDINGS =
  "M9 12.75 11.25 15 15 9.75M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0Z"
const ICON_CHAINS =
  "M4 6l8 12 8-12M4 18h16"
const ICON_INBOX =
  "M3.75 6.75h16.5M3.75 12h16.5m-16.5 5.25h16.5"
const ICON_ACTIVITY =
  "M3.75 13.5l10.5-11.25L12 10.5h8.25L9.75 21.75 12 13.5H3.75Z"
const ICON_POSTURE =
  "M2.25 18 9 11.25l4.306 4.306a11.95 11.95 0 0 1 5.814-5.518l2.74-1.22m0 0-5.94-2.281m5.94 2.28-2.28 5.941"
const ICON_REPORTS =
  "M9 17.25v1.007a3 3 0 0 1-.879 2.122L7.5 21h9l-.621-.621A3 3 0 0 1 15 18.257V17.25m6-12V15a2.25 2.25 0 0 1-2.25 2.25H5.25A2.25 2.25 0 0 1 3 15V5.25m18 0A2.25 2.25 0 0 0 18.75 3H5.25A2.25 2.25 0 0 0 3 5.25m18 0V12a2.25 2.25 0 0 1-2.25 2.25H5.25A2.25 2.25 0 0 1 3 12V5.25"
const ICON_INTEGRATIONS_PLUG =
  "M21.75 6.75a4.5 4.5 0 0 1-4.884 4.484c-1.076-.091-2.264.071-2.95.904l-7.152 8.684a2.548 2.548 0 1 1-3.586-3.586l8.684-7.152c.833-.686.995-1.874.904-2.95a4.5 4.5 0 0 1 6.336-4.486l-3.276 3.276a3.004 3.004 0 0 0 2.25 2.25l3.276-3.276c.256.565.398 1.192.398 1.852Z M4.867 19.125h.008v.008h-.008v-.008Z"
const ICON_NOTIFICATIONS =
  "M14.857 17.082a23.848 23.848 0 0 0 5.454-1.31A8.967 8.967 0 0 1 18 9.75V9A6 6 0 0 0 6 9v.75a8.967 8.967 0 0 1-2.312 6.022c1.733.64 3.56 1.085 5.455 1.31m5.714 0a24.255 24.255 0 0 1-5.714 0m5.714 0a3 3 0 1 1-5.714 0"
const ICON_POLICIES =
  "M19.5 14.25v-2.625a3.375 3.375 0 0 0-3.375-3.375h-1.5A1.125 1.125 0 0 1 13.5 7.125v-1.5a3.375 3.375 0 0 0-3.375-3.375H8.25m0 12.75h7.5m-7.5 3H12M10.5 2.25H5.625c-.621 0-1.125.504-1.125 1.125v17.25c0 .621.504 1.125 1.125 1.125h12.75c.621 0 1.125-.504 1.125-1.125V11.25a9 9 0 0 0-9-9Z"
const ICON_REPOS =
  "M21 7.5l-9-5.25L3 7.5m18 0l-9 5.25m9-5.25v9l-9 5.25M3 7.5l9 5.25M3 7.5v9l9 5.25m0-9v9"
const ICON_RELEASES =
  "M9 12.75 11.25 15 15 9.75M3.75 9.75h16.5M3.75 9.75A2.25 2.25 0 0 1 6 7.5h12a2.25 2.25 0 0 1 2.25 2.25v9A2.25 2.25 0 0 1 18 21H6a2.25 2.25 0 0 1-2.25-2.25v-9ZM7.5 7.5V5.25A2.25 2.25 0 0 1 9.75 3h4.5a2.25 2.25 0 0 1 2.25 2.25V7.5"
const ICON_DATABASE =
  "M4 7v10c0 2.21 3.58 4 8 4s8-1.79 8-4V7M4 7c0 2.21 3.58 4 8 4s8-1.79 8-4M4 7c0-2.21 3.58-4 8-4s8 1.79 8 4"
const ICON_SBOM =
  "M3.75 12h16.5m-16.5 3.75h16.5M3.75 19.5h16.5M5.625 4.5h12.75a1.875 1.875 0 0 1 0 3.75H5.625a1.875 1.875 0 0 1 0-3.75Z"

const ICON_COMPLIANCE =
  "M9 12.75 11.25 15 15 9.75m-3-7.036A11.959 11.959 0 0 1 3.598 6 11.99 11.99 0 0 0 3 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285Z"

const ICON_MEMBERS =
  "M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2 M22 21v-2a4 4 0 0 0-3-3.87 M16 3.13a4 4 0 0 1 0 7.75 M9 7a4 4 0 1 1-8 0 4 4 0 0 1 8 0z"
const ICON_ROLES =
  "M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z m-3-10 2 2 4-4"
const ICON_TEAMS =
  "M17 21v-2a4 4 0 0 0-3-3.87 M7 21v-2a4 4 0 0 1 3-3.87 M16 7a4 4 0 1 1-8 0 4 4 0 0 1 8 0z"

function NavIcon({ d }: { d: string }) {
  return (
    <svg
      className="h-5 w-5 shrink-0"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={1.5}
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <path d={d} />
    </svg>
  )
}

type CountTone = "neutral" | "danger"

interface NavItem {
  href: string
  label: string
  icon: string
  badge?: string
  count?: number
  countTone?: CountTone
}

function NavItemCount({ count, tone }: { count: number; tone: CountTone }) {
  const className =
    tone === "danger"
      ? "ml-auto shrink-0 rounded-full bg-[var(--color-severity-critical-subtle)] px-1.5 py-px text-2xs font-semibold tabular-nums text-[var(--color-severity-critical)]"
      : "ml-auto shrink-0 rounded-full bg-[var(--color-surface-raised)] px-1.5 py-px text-2xs font-semibold tabular-nums text-[var(--color-text-secondary)]"
  return <span className={className}>{count.toLocaleString()}</span>
}

export function SidebarContent({
  dependenciesEnabled: _dependenciesEnabled,
  container_scanningEnabled: _container_scanningEnabled,
  secretsEnabled: _secretsEnabled,
  code_scanningEnabled: _code_scanningEnabled,
  iacEnabled: _iacEnabled,
  navCounts,
  orgCount,
  collapsed,
  onNavigate,
  scanningTools: _scanningTools,
  searchOpen,
  onSearchOpen,
}: SidebarContentProps) {
  const pathname = useMountedPathname()
  const { tier } = useLicense()
  const { name: brandName, isVendor } = useBranding()

  const tierCardStyles: Record<Tier, { border: string; icon: string; label: string }> = {
    community: {
      border: "border-[var(--color-accent)]/20 bg-[var(--color-accent-subtle)] hover:border-[var(--color-accent)]/40",
      icon: "text-[var(--color-accent)]",
      label: "text-[var(--color-accent)]",
    },
    enterprise: {
      border: "border-[var(--color-state-dismissed-border)] bg-[var(--color-state-dismissed-subtle)] hover:border-[var(--color-state-dismissed)]/40",
      icon: "text-[var(--color-state-dismissed)]",
      label: "text-[var(--color-state-dismissed)]",
    },
  }

  // Overview: at-a-glance landing surfaces (devs → Home, analysts → Inbox /
  // Findings, execs → Posture). /activity intentionally lives outside the
  // sidebar — users reach it via the notification bell in the header.
  const overviewItems: NavItem[] = [
    { href: "/", label: "Home", icon: ICON_HOME },
    { href: "/inbox", label: "Inbox", icon: ICON_INBOX, count: navCounts?.inbox, countTone: "danger" },
    { href: "/findings", label: "Findings", icon: ICON_FINDINGS, count: navCounts?.findings, countTone: "neutral" },
    { href: "/posture", label: "Posture", icon: ICON_POSTURE },
  ];

  // Reporting: audit-ready deliverables and exec views
  const reportingItems: NavItem[] = [
    { href: "/compliance", label: "Compliance", icon: ICON_COMPLIANCE },
    { href: "/reports", label: "Reports", icon: ICON_REPORTS },
  ];

  // Configuration: outbound routing rules and org-wide policies
  const configurationItems: NavItem[] = [
    { href: "/policies", label: "Policies", icon: ICON_POLICIES },
    { href: "/integrations", label: "Integrations", icon: ICON_INTEGRATIONS_PLUG },
    { href: "/notifications", label: "Notifications", icon: ICON_NOTIFICATIONS },
  ];

  // Data: inventory of what Aegis is watching. /releases is intentionally
  // absent — releases are reached from /sources/[id] → Pre-release scan.
  const dataItems: NavItem[] = [
    { href: "/sources", label: "Sources", icon: ICON_DATABASE },
    { href: "/sbom", label: "SBOM", icon: ICON_SBOM },
    { href: "/chains", label: "Chains", icon: ICON_CHAINS, badge: "Preview" },
  ];

  // Workspace: people and access. Promoted out of /settings so admins can
  // reach Members / Roles / Teams in one click instead of three.
  const workspaceItems: NavItem[] = [
    { href: "/members", label: "Members", icon: ICON_MEMBERS },
    { href: "/roles", label: "Roles", icon: ICON_ROLES },
    { href: "/teams", label: "Teams", icon: ICON_TEAMS },
  ];

  const isActive = (href: string) => {
    if (!pathname) return false
    if (href === "/") return pathname === "/"
    if (href === "#") return false
    return pathname.startsWith(href)
  }

  function navLinkClass(active: boolean) {
    return `flex items-center gap-2.5 rounded-lg py-2 text-sm transition-colors ${
      collapsed ? "justify-center px-2" : "pl-2.5 pr-2.5"
    } ${
      active
        ? "bg-[var(--color-nav-active)] text-[var(--color-accent)]"
        : "text-[var(--color-text-secondary)] hover:bg-[var(--color-surface-raised)] hover:text-[var(--color-text-primary)]"
    }`
  }

  function GroupLabel({ label }: { label: string }) {
    if (collapsed) return <div className="mt-2" />
    return (
      <p className="mt-3 mb-1 px-2.5 text-2xs font-semibold uppercase tracking-[0.14em] text-[var(--color-text-secondary)]">
        {label}
      </p>
    )
  }

  return (
    <>
      {/* Branding — vendor identity (3-line) when name is NULL; customer (2-line) otherwise */}
      <div className="flex items-center gap-3 border-b border-[var(--color-border)] px-4 py-3 shrink-0 overflow-hidden">
        {!collapsed && (
          <div className="flex items-center gap-3 min-w-0">
            <BrandLogo className="h-11 w-11 shrink-0 object-contain" />
            <div className="flex min-w-0 flex-col">
              {isVendor ? (
                <>
                  <span className="font-[family-name:var(--font-space-grotesk)] text-[0.6rem] font-bold uppercase tracking-[0.28em] text-[var(--color-text-secondary)]">
                    Raven Protocol
                  </span>
                  <span className="font-[family-name:var(--font-space-grotesk)] text-[1.15rem] font-bold leading-none tracking-[-0.04em] text-[var(--color-text-primary)]">
                    Blu3Raven
                  </span>
                  <span className="mt-0.5 text-2xs leading-tight text-[var(--color-text-secondary)]">
                    Aegis — Vulnerability Management Portal
                  </span>
                </>
              ) : (
                <span className="font-[family-name:var(--font-space-grotesk)] text-[1.15rem] font-bold leading-none tracking-[-0.04em] text-[var(--color-text-primary)] truncate">
                  {brandName}
                </span>
              )}
            </div>
          </div>
        )}
        {collapsed && (
          <BrandLogo className="h-9 w-9 shrink-0 object-contain" />
        )}
      </div>

      {/* Main nav items */}
      <div className="flex flex-col gap-0.5 p-2 flex-1 min-h-0 overflow-y-auto">
        {/* Search trigger */}
        {onSearchOpen && (
          collapsed ? (
            <Tooltip content="Search">
              <button
                type="button"
                onClick={() => onSearchOpen(!searchOpen)}
                aria-label="Search"
                className="flex w-full items-center justify-center rounded-lg py-2 px-2 text-[var(--color-text-secondary)] transition-colors hover:bg-[var(--color-surface-raised)] hover:text-[var(--color-text-primary)]"
              >
                <svg className="h-5 w-5 shrink-0" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.5} strokeLinecap="round" strokeLinejoin="round">
                  <path d={ICON_SEARCH} />
                </svg>
              </button>
            </Tooltip>
          ) : (
            <button
              type="button"
              onClick={() => onSearchOpen(!searchOpen)}
              className="mb-1 flex w-full items-center gap-2 rounded-lg border border-[var(--color-border)] bg-[var(--color-bg)] px-2.5 py-2 text-xs text-[var(--color-text-secondary)] transition-colors hover:border-[var(--color-accent)] hover:text-[var(--color-text-primary)]"
            >
              <svg className="h-3 w-3 shrink-0" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.8} strokeLinecap="round" strokeLinejoin="round">
                <path d={ICON_SEARCH} />
              </svg>
              <span className="flex-1 text-left">Search…</span>
              <kbd className="rounded border border-[var(--color-border)] px-1 py-px font-mono text-2xs text-[var(--color-text-secondary)]">⌘K</kbd>
            </button>
          )
        )}

        {/* Overview — at-a-glance landing surfaces */}
        <GroupLabel label="Overview" />
        {overviewItems.map((item) => {
          const active = isActive(item.href)
          const link = (
            <Link
              key={item.href}
              href={item.href}
              title={collapsed ? item.label : undefined}
              aria-label={collapsed ? item.label : undefined}
              onClick={onNavigate}
              className={navLinkClass(active)}
            >
              <NavIcon d={item.icon} />
              {!collapsed && (
                <>
                  <span className="truncate">{item.label}</span>
                  {item.count != null && item.count > 0 && (
                    <NavItemCount count={item.count} tone={item.countTone ?? "neutral"} />
                  )}
                </>
              )}
            </Link>
          )
          return collapsed ? <Tooltip key={item.href} content={item.label}>{link}</Tooltip> : link
        })}

        {/* Inventory — what Aegis is watching (ASPM-standard vocabulary) */}
        <GroupLabel label="Inventory" />
        {dataItems.map((item) => {
          const active = isActive(item.href)
          const link = (
            <Link
              key={item.href}
              href={item.href}
              title={collapsed ? item.label : undefined}
              aria-label={collapsed ? item.label : undefined}
              onClick={onNavigate}
              className={navLinkClass(active)}
            >
              <NavIcon d={item.icon} />
              {!collapsed && (
                <>
                  <span className="truncate">{item.label}</span>
                  {item.badge && (
                    <span className="ml-auto shrink-0 rounded border border-[var(--color-state-dismissed-border)] bg-[var(--color-state-dismissed-subtle)] px-1.5 py-px text-2xs font-bold uppercase tracking-[0.08em] text-[var(--color-state-dismissed)]">
                      {item.badge}
                    </span>
                  )}
                  {!item.badge && item.count != null && item.count > 0 && (
                    <NavItemCount count={item.count} tone={item.countTone ?? "neutral"} />
                  )}
                </>
              )}
            </Link>
          )
          return collapsed ? <Tooltip key={item.href} content={item.label}>{link}</Tooltip> : link
        })}

        {/* Workspace — people and access */}
        <GroupLabel label="Workspace" />
        {workspaceItems.map((item) => {
          const active = isActive(item.href)
          const link = (
            <Link
              key={item.href}
              href={item.href}
              title={collapsed ? item.label : undefined}
              aria-label={collapsed ? item.label : undefined}
              onClick={onNavigate}
              className={navLinkClass(active)}
            >
              <NavIcon d={item.icon} />
              {!collapsed && <span className="truncate">{item.label}</span>}
            </Link>
          )
          return collapsed ? <Tooltip key={item.href} content={item.label}>{link}</Tooltip> : link
        })}

        {/* Insights — audit + exec deliverables */}
        <GroupLabel label="Insights" />
        {reportingItems.map((item) => {
          const active = isActive(item.href)
          const link = (
            <Link
              key={item.href}
              href={item.href}
              title={collapsed ? item.label : undefined}
              aria-label={collapsed ? item.label : undefined}
              onClick={onNavigate}
              className={navLinkClass(active)}
            >
              <NavIcon d={item.icon} />
              {!collapsed && (
                <>
                  <span className="truncate">{item.label}</span>
                  {item.count != null && item.count > 0 && (
                    <NavItemCount count={item.count} tone={item.countTone ?? "neutral"} />
                  )}
                </>
              )}
            </Link>
          )
          return collapsed ? <Tooltip key={item.href} content={item.label}>{link}</Tooltip> : link
        })}

        {/* Configure — routing + policies */}
        <GroupLabel label="Configure" />
        {configurationItems.map((item) => {
          const active = isActive(item.href)
          const link = (
            <Link
              key={item.href}
              href={item.href}
              title={collapsed ? item.label : undefined}
              aria-label={collapsed ? item.label : undefined}
              onClick={onNavigate}
              className={navLinkClass(active)}
            >
              <NavIcon d={item.icon} />
              {!collapsed && <span className="truncate">{item.label}</span>}
            </Link>
          )
          return collapsed ? <Tooltip key={item.href} content={item.label}>{link}</Tooltip> : link
        })}
      </div>

      {/* Footer: tier plan + user profile */}
      <div className="p-2 border-t border-[var(--color-border)] flex flex-col gap-0.5">
        {!collapsed && (
          <Link
            href="/settings/license"
            className={`mx-2 mt-2 flex items-center gap-2 rounded-xl border px-3 py-2.5 transition-colors ${tierCardStyles[tier].border}`}
          >
            <svg className={`h-3.5 w-3.5 shrink-0 ${tierCardStyles[tier].icon}`} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
              <path d="M9.813 15.904 9 18.75l-.813-2.846a4.5 4.5 0 0 0-3.09-3.09L2.25 12l2.846-.813a4.5 4.5 0 0 0 3.09-3.09L9 5.25l.813 2.846a4.5 4.5 0 0 0 3.09 3.09L15.75 12l-2.846.813a4.5 4.5 0 0 0-3.09 3.09ZM18.259 8.715 18 9.75l-.259-1.035a3.375 3.375 0 0 0-2.455-2.456L14.25 6l1.036-.259a3.375 3.375 0 0 0 2.455-2.456L18 2.25l.259 1.035a3.375 3.375 0 0 0 2.456 2.456L21.75 6l-1.035.259a3.375 3.375 0 0 0-2.456 2.456Z" />
            </svg>
            <span className={`text-[11px] font-semibold ${tierCardStyles[tier].label}`}>
              {TIER_LABELS[tier]}
            </span>
            <span className="text-[11px] text-[var(--color-text-secondary)]">
              {tier === "community" ? "· Free tier" : "· Plan"}
            </span>
          </Link>
        )}
        <div className="mt-2">
          <UserMenuButton variant="footer" collapsed={collapsed} />
        </div>
      </div>
    </>
  )
}
