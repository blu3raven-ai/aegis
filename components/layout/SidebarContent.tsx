"use client"

import Link from "next/link"
import { usePathname } from "next/navigation"
import { Tooltip } from "@/components/layout/Tooltip"
import { UserMenuButton } from "@/components/layout/UserMenuButton"
import { BrandLogo } from "@/components/layout/BrandLogo"
import { useLicense } from "@/lib/client/license/client"
import { TIER_LABELS } from "@/lib/shared/license/types"
import type { Tier } from "@/lib/shared/license/types"

const ICON_SEARCH = "M21 21l-5.197-5.197m0 0A7.5 7.5 0 1 0 5.196 5.196a7.5 7.5 0 0 0 10.607 10.607Z"

export interface SidebarContentProps {
  dependenciesEnabled: boolean
  containerScanningEnabled: boolean
  secretsEnabled: boolean
  codeScanningEnabled: boolean
  iacEnabled: boolean
  counts?: { dependencies?: number; containerScanning?: number; secrets?: number; codeScanning?: number }
  orgName?: string
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
  onboardingComplete?: boolean
}

const ICON_HOME =
  "M2.25 12l8.954-8.955c.44-.439 1.152-.439 1.591 0L21.75 12M4.5 9.75v10.125c0 .621.504 1.125 1.125 1.125H9.75v-4.875c0-.621.504-1.125 1.125-1.125h2.25c.621 0 1.125.504 1.125 1.125V21h4.125c.621 0 1.125-.504 1.125-1.125V9.75M8.25 21h8.25"
const ICON_SCA =
  "M9 12.75 11.25 15 15 9.75m-3-7.036A11.959 11.959 0 0 1 3.598 6 11.99 11.99 0 0 0 3 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285Z"
const ICON_SECRETS =
  "M15.75 5.25a3 3 0 0 1 3 3m3 0a6 6 0 0 1-7.029 5.912c-.563-.097-1.159.026-1.563.43L10.5 17.25H8.25v2.25H6v2.25H2.25v-2.818c0-.597.237-1.17.659-1.591l6.499-6.499c.404-.404.527-1 .43-1.563A6 6 0 1 1 21.75 8.25Z"
const ICON_SAST =
  "M17.25 6.75 22.5 12l-5.25 5.25m-10.5 0L1.5 12l5.25-5.25m7.5-3-4.5 16.5"
const ICON_IAC =
  "M3.75 6.75 12 2.25l8.25 4.5v10.5L12 21.75l-8.25-4.5V6.75Zm5.25 3.75L12 12m0 0 3-1.5M12 12v3.75"
const ICON_CONTAINER =
  "M21 7.5l-9-5.25L3 7.5m18 0l-9 5.25m9-5.25v9l-9 5.25M3 7.5l9 5.25M3 7.5v9l9 5.25m0-9v9"
const ICON_SBOM =
  "M3.75 12h16.5m-16.5 3.75h16.5M3.75 19.5h16.5M5.625 4.5h12.75a1.875 1.875 0 0 1 0 3.75H5.625a1.875 1.875 0 0 1 0-3.75Z"

const ICON_ONBOARDING =
  "M9 12.75 11.25 15 15 9.75M21 12c0 1.268-.63 2.39-1.593 3.068a3.745 3.745 0 0 1-1.043 3.296 3.745 3.745 0 0 1-3.296 1.043A3.745 3.745 0 0 1 12 21c-1.268 0-2.39-.63-3.068-1.593a3.745 3.745 0 0 1-3.296-1.043 3.745 3.745 0 0 1-1.043-3.296A3.745 3.745 0 0 1 3 12c0-1.268.63-2.39 1.593-3.068a3.745 3.745 0 0 1 1.043-3.296 3.745 3.745 0 0 1 3.296-1.043A3.746 3.746 0 0 1 12 3c1.268 0 2.39.63 3.068 1.593a3.746 3.746 0 0 1 3.296 1.043 3.746 3.746 0 0 1 1.043 3.296A3.745 3.745 0 0 1 21 12Z"

const ICON_FINDINGS =
  "M9 12.75 11.25 15 15 9.75M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0Z"
const ICON_CHAINS =
  "M4 6l8 12 8-12M4 18h16"

const ICON_SOURCES =
  "M3.75 7.5a2.25 2.25 0 0 1 2.25-2.25h12A2.25 2.25 0 0 1 20.25 7.5v9A2.25 2.25 0 0 1 18 18.75H6a2.25 2.25 0 0 1-2.25-2.25v-9Zm4.5 3 2.25 2.25-2.25 2.25m4.5 0h3"
const ICON_COMPLIANCE =
  "M9 12.75 11.25 15 15 9.75m-3-7.036A11.959 11.959 0 0 1 3.598 6 11.99 11.99 0 0 0 3 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285Z"

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

interface NavItem {
  href: string
  label: string
  icon: string
  enabled: boolean
  count?: number
}

export function SidebarContent({
  dependenciesEnabled,
  containerScanningEnabled,
  secretsEnabled,
  codeScanningEnabled,
  iacEnabled,
  counts,
  orgName,
  orgCount,
  collapsed,
  onNavigate,
  scanningTools,
  searchOpen,
  onSearchOpen,
  onboardingComplete = true,
}: SidebarContentProps) {
  const pathname = usePathname()
  const { tier } = useLicense()

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

  // Work: high-level destinations the user starts from each day
  const workItems: NavItem[] = [
    { href: "/", label: "Home", icon: ICON_HOME, enabled: true },
    { href: "/findings", label: "Findings", icon: ICON_FINDINGS, enabled: true },
    { href: "/chains", label: "Chains", icon: ICON_CHAINS, enabled: true },
  ]

  // Scanners: per-tool dashboards
  const scannerItems: NavItem[] = [
    { href: "/dependencies/dashboard", label: "Dependencies", icon: ICON_SCA, enabled: dependenciesEnabled, count: counts?.dependencies },
    { href: "/containers/dashboard", label: "Containers", icon: ICON_CONTAINER, enabled: containerScanningEnabled, count: counts?.containerScanning },
    { href: "/code/dashboard", label: "Code", icon: ICON_SAST, enabled: codeScanningEnabled, count: counts?.codeScanning },
    { href: "/secrets/dashboard", label: "Secrets", icon: ICON_SECRETS, enabled: secretsEnabled, count: counts?.secrets },
    { href: "/iac/dashboard", label: "IaC Security", icon: ICON_IAC, enabled: iacEnabled },
  ]

  // Library: durable inventory and reference surfaces
  const libraryItems: NavItem[] = [
    { href: "/sbom", label: "SBOM", icon: ICON_SBOM, enabled: true },
    { href: "/compliance", label: "Compliance", icon: ICON_COMPLIANCE, enabled: true },
    { href: "/sources", label: "Sources", icon: ICON_SOURCES, enabled: true },
  ]

  const isActive = (href: string) => {
    if (href === "/") return pathname === "/"
    if (href === "#") return false
    if (href === "/sbom") return pathname === "/sbom" || pathname.startsWith("/sbom/")
    if (href === "/sources") return pathname === "/sources" || pathname.startsWith("/sources/")
    const base = href.split("/dashboard")[0]
    return pathname.startsWith(base)
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
      {/* Branding */}
      <div className="flex items-center gap-3 border-b border-[var(--color-border)] px-4 py-3 shrink-0 overflow-hidden">
        {!collapsed && (
          <div className="flex items-center gap-3 min-w-0">
            <BrandLogo className="h-11 w-11 shrink-0 object-contain" />
            <div className="flex min-w-0 flex-col">
              <span className="font-[family-name:var(--font-space-grotesk)] text-[0.6rem] font-bold uppercase tracking-[0.28em] text-[var(--color-text-secondary)]">
                Raven Protocol
              </span>
              <span className="font-[family-name:var(--font-space-grotesk)] text-[1.15rem] font-bold leading-none tracking-[-0.04em] text-[var(--color-text-primary)]">
                Blu3Raven
              </span>
              <span className="mt-0.5 text-2xs leading-tight text-[var(--color-text-secondary)]">
                Aegis — Vulnerability Management Portal
              </span>
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

        {/* Onboarding — visible until wizard is dismissed */}
        {!onboardingComplete && (() => {
          const active = pathname === "/onboarding"
          const link = (
            <Link
              href="/onboarding"
              onClick={onNavigate}
              className={navLinkClass(active)}
            >
              <span className="relative shrink-0">
                <NavIcon d={ICON_ONBOARDING} />
                <span
                  className="absolute -right-0.5 -top-0.5 h-[7px] w-[7px] rounded-full bg-amber-500 ring-2 ring-[var(--color-surface)]"
                  aria-hidden="true"
                />
              </span>
              {!collapsed && (
                <>
                  <span className="truncate">Onboarding</span>
                  <span className="ml-auto shrink-0 rounded-full border border-amber-500/30 bg-amber-500/10 px-1.5 py-px text-[10px] font-semibold text-amber-500">
                    Incomplete
                  </span>
                </>
              )}
            </Link>
          )
          return collapsed ? <Tooltip content="Onboarding (incomplete)">{link}</Tooltip> : link
        })()}

        {/* Work group */}
        <GroupLabel label="Work" />
        {workItems.map((item) => {
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

        {/* Scanners group */}
        <GroupLabel label="Scanners" />
        {scannerItems.map((item) => {
          const active = isActive(item.href)
          const isScanning = collapsed && scanningTools?.includes(item.label)
          const link = (
            <Link
              key={item.href}
              href={item.href}
              title={collapsed ? item.label : undefined}
              aria-label={collapsed ? item.label : undefined}
              onClick={onNavigate}
              className={navLinkClass(active)}
            >
              <span className={`relative shrink-0${isScanning ? " animate-[scan-pulse_2s_ease-in-out_infinite] text-[var(--color-accent)]" : ""}`}>
                <NavIcon d={item.icon} />
                {collapsed && typeof item.count === "number" && item.count > 0 && (
                  <span
                    className="absolute -right-0.5 -top-0.5 h-[7px] w-[7px] rounded-full bg-[var(--color-accent)] ring-2 ring-[var(--color-surface)]"
                    aria-hidden="true"
                  />
                )}
              </span>
              {!collapsed && <span className="truncate">{item.label}</span>}
              {!collapsed && typeof item.count === "number" && item.count > 0 && (
                <span className="ml-auto shrink-0 rounded-full bg-[var(--color-surface-raised)] px-1.5 py-0.5 text-2xs tabular-nums text-[var(--color-text-secondary)]">
                  {item.count}
                </span>
              )}
            </Link>
          )
          return collapsed ? <Tooltip key={item.href} content={item.label}>{link}</Tooltip> : link
        })}

        {/* Library group */}
        <GroupLabel label="Library" />
        {libraryItems.map((item) => {
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
