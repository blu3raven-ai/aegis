"use client"

import { useEffect, useState } from "react"
import Link from "next/link"
import { usePathname } from "next/navigation"
import { fetchCurrentUser, type CurrentUser } from "@/lib/client/auth"
import { can } from "@/lib/shared/auth/roles.ts"
import { listOrganisationTeams } from "@/lib/client/settings-api"

const ICON_ACCOUNT =
  "M15.75 5.25a3.75 3.75 0 1 1-7.5 0 3.75 3.75 0 0 1 7.5 0ZM4.501 20.118a7.5 7.5 0 0 1 14.998 0A17.933 17.933 0 0 1 12 21.75c-2.676 0-5.216-.584-7.499-1.632Z"

const ICON_USERS =
  "M9 11a3 3 0 1 0 0-6 3 3 0 0 0 0 6ZM3.75 19c0-2.35 2.35-4.25 5.25-4.25S14.25 16.65 14.25 19M16.5 11a2.5 2.5 0 1 0 0-5M15.75 14.75c2.55.25 4.5 2 4.5 4.25"


const ICON_ROLES =
  "M12 2.714A11.959 11.959 0 0 1 3.598 6 11.99 11.99 0 0 0 3 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285Z"

const ICON_ORGS =
  "M3.75 21h16.5M4.5 3h15M5.25 3v18m13.5-18v18M9 6.75h1.5m-1.5 3h1.5m-1.5 3h1.5m3-6H15m-1.5 3H15m-1.5 3H15M9 21v-3.375c0-.621.504-1.125 1.125-1.125h3.75c.621 0 1.125.504 1.125 1.125V21"

const ICON_RUNNERS =
  "M21.75 17.25v-.228a4.5 4.5 0 0 0-.12-1.03l-2.268-9.64a3.375 3.375 0 0 0-3.285-2.602H7.923a3.375 3.375 0 0 0-3.285 2.602l-2.268 9.64a4.5 4.5 0 0 0-.12 1.03v.228m19.5 0a3 3 0 0 1-3 3H5.25a3 3 0 0 1-3-3m19.5 0a3 3 0 0 0-3-3H5.25a3 3 0 0 0-3 3m16.5 0h.008v.008h-.008v-.008Zm-3 0h.008v.008h-.008v-.008Z"

const ICON_LICENSE =
  "M16.5 10.5V6.75a4.5 4.5 0 1 0-9 0v3.75m-.75 11.25h10.5a2.25 2.25 0 0 0 2.25-2.25v-6.75a2.25 2.25 0 0 0-2.25-2.25H6.75a2.25 2.25 0 0 0-2.25 2.25v6.75a2.25 2.25 0 0 0 2.25 2.25Z"

const ICON_SSO =
  "M15.75 5.25a3 3 0 0 1 3 3m3 0a6 6 0 0 1-7.029 5.912c-.563-.097-1.159.026-1.563.43L10.5 17.25H8.25v2.25H6v2.25H2.25v-2.818c0-.597.237-1.17.659-1.591l6.499-6.499c.404-.404.527-1 .43-1.563A6 6 0 1 1 21.75 8.25Z"

const ICON_AUDIT_LOG =
  "M19.5 14.25v-2.625a3.375 3.375 0 0 0-3.375-3.375h-1.5A1.125 1.125 0 0 1 13.5 7.125v-1.5a3.375 3.375 0 0 0-3.375-3.375H8.25m0 12.75h7.5m-7.5 3H12M10.5 2.25H5.625c-.621 0-1.125.504-1.125 1.125v17.25c0 .621.504 1.125 1.125 1.125h12.75c.621 0 1.125-.504 1.125-1.125V11.25a9 9 0 0 0-9-9Z"

interface NavItem {
  href: string
  label: string
  icon: string
  meta?: string       // for workspace items: shows count on right
}

const YOU_NAV: NavItem[] = [
  { href: "/settings/account", label: "Account", icon: ICON_ACCOUNT },
]

function NavLink({ item, active }: { item: NavItem; active: boolean }) {
  return (
    <Link
      href={item.href}
      className={`flex items-center gap-2.5 rounded-lg py-[7px] pl-[10px] pr-3 text-[12.5px] transition-colors border-l-2 ${
        active
          ? "border-[var(--color-accent)] bg-[var(--color-nav-active)] text-[var(--color-text-primary)]"
          : "border-transparent text-[var(--color-text-secondary)] hover:bg-[var(--color-surface-raised)] hover:text-[var(--color-text-primary)]"
      }`}
    >
      <svg
        className="h-3.5 w-3.5 shrink-0"
        viewBox="0 0 24 24"
        fill="none"
        stroke="currentColor"
        strokeWidth={1.5}
        strokeLinecap="round"
        strokeLinejoin="round"
      >
        <path d={item.icon} />
      </svg>
      <span className="hidden flex-1 truncate md:inline">{item.label}</span>
      {item.meta && (
        <span className="hidden shrink-0 font-mono text-[10px] text-[var(--color-text-secondary)] md:inline">
          {item.meta}
        </span>
      )}
    </Link>
  )
}

function NavGroup({ label, items, pathname }: { label: string; items: NavItem[]; pathname: string }) {
  return (
    <div>
      <div className="hidden md:block px-[10px] pb-1.5 text-[10px] font-semibold uppercase tracking-[0.12em] text-[var(--color-text-secondary)]">
        {label}
      </div>
      <div className="flex flex-row md:flex-col gap-0.5">
        {items.map((item) => (
          <NavLink key={item.href} item={item} active={pathname === item.href || pathname.startsWith(item.href + "/")} />
        ))}
      </div>
    </div>
  )
}

export interface SidebarNavProps {
  teamCount?: number
  roleCount?: number
  memberCount?: number
}

export function SidebarNav({
  teamCount,
  roleCount,
  memberCount,
}: SidebarNavProps) {
  const pathname = usePathname()
  const [user, setUser] = useState<CurrentUser | null>(null)
  const [isTeamAdmin, setIsTeamAdmin] = useState(false)

  const workspaceNav: NavItem[] = [
    { href: "/settings/organisations", label: "Teams", icon: ICON_ORGS, meta: teamCount !== undefined ? String(teamCount) : undefined },
    { href: "/settings/users", label: "Members", icon: ICON_USERS, meta: memberCount !== undefined ? String(memberCount) : undefined },
  ]

  if (user && can(user.role, "manage_settings")) {
    workspaceNav.push({ href: "/settings/roles", label: "Roles", icon: ICON_ROLES, meta: roleCount !== undefined ? String(roleCount) : undefined })
  }

  const securityNav: NavItem[] = [
    { href: "/settings/sso", label: "SSO", icon: ICON_SSO },
    { href: "/settings/audit-log", label: "Audit Log", icon: ICON_AUDIT_LOG },
  ]

  const infraNav: NavItem[] = [
    { href: "/settings/runners", label: "Runners", icon: ICON_RUNNERS },
    { href: "/settings/license", label: "License", icon: ICON_LICENSE },
  ]

  useEffect(() => {
    void fetchCurrentUser().then((u) => {
      setUser(u)
      if (u && !can(u.role, "manage_settings")) {
        void listOrganisationTeams().then(res => {
          if (res.ok && res.teams.length > 0) setIsTeamAdmin(true)
        })
      }
    })
  }, [pathname])

  const canViewWorkspace = user ? (can(user.role, "manage_settings") || isTeamAdmin) : false
  const canViewConfig = user ? can(user.role, "manage_settings") : false

  return (
    <nav className="shrink-0 w-full bg-[var(--color-surface)] flex flex-row md:flex-col md:w-[248px] md:border-r md:border-[var(--color-border)] md:h-full">
      <div className="flex flex-row md:flex-col gap-4 overflow-x-auto px-2.5 py-3 md:overflow-x-visible md:flex-1">
        <NavGroup label="You" items={YOU_NAV} pathname={pathname} />

        {canViewWorkspace && (
          <NavGroup label="Workspace" items={workspaceNav} pathname={pathname} />
        )}
        {canViewConfig && (
          <NavGroup label="Security" items={securityNav} pathname={pathname} />
        )}
        {canViewConfig && (
          <NavGroup label="System" items={infraNav} pathname={pathname} />
        )}
      </div>
    </nav>
  )
}
