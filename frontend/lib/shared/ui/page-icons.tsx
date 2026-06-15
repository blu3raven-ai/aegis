import type { ReactNode } from "react"

interface IconChipProps {
  children: ReactNode
}

function IconChip({ children }: IconChipProps) {
  return (
    <div className="p-1.5 bg-[var(--color-accent-subtle)] rounded-lg">
      <svg
        xmlns="http://www.w3.org/2000/svg"
        className="w-5 h-5 text-[var(--color-accent)]"
        fill="none"
        viewBox="0 0 24 24"
        stroke="currentColor"
        strokeWidth={1.5}
        strokeLinecap="round"
        strokeLinejoin="round"
        aria-hidden="true"
      >
        {children}
      </svg>
    </div>
  )
}

export function FindingsIcon() {
  return (
    <IconChip>
      <path d="M9 12.75 11.25 15 15 9.75M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0Z" />
    </IconChip>
  )
}

export function ChainsIcon() {
  return (
    <IconChip>
      <path d="M4 6l8 12 8-12M4 18h16" />
    </IconChip>
  )
}

export function ReposIcon() {
  return (
    <IconChip>
      <path d="M3.75 6A2.25 2.25 0 0 1 6 3.75h2.25A2.25 2.25 0 0 1 10.5 6v2.25a2.25 2.25 0 0 1-2.25 2.25H6a2.25 2.25 0 0 1-2.25-2.25V6ZM3.75 15.75A2.25 2.25 0 0 1 6 13.5h2.25a2.25 2.25 0 0 1 2.25 2.25V18a2.25 2.25 0 0 1-2.25 2.25H6A2.25 2.25 0 0 1 3.75 18v-2.25ZM13.5 6a2.25 2.25 0 0 1 2.25-2.25H18A2.25 2.25 0 0 1 20.25 6v2.25A2.25 2.25 0 0 1 18 10.5h-2.25a2.25 2.25 0 0 1-2.25-2.25V6ZM13.5 15.75a2.25 2.25 0 0 1 2.25-2.25H18a2.25 2.25 0 0 1 2.25 2.25V18A2.25 2.25 0 0 1 18 20.25h-2.25A2.25 2.25 0 0 1 13.5 18v-2.25Z" />
    </IconChip>
  )
}

export function SbomIcon() {
  return (
    <IconChip>
      <path d="M3.75 12h16.5m-16.5 3.75h16.5M3.75 19.5h16.5M5.625 4.5h12.75a1.875 1.875 0 0 1 0 3.75H5.625a1.875 1.875 0 0 1 0-3.75Z" />
    </IconChip>
  )
}

export function SbomDiffIcon() {
  return (
    <IconChip>
      <path d="M7.5 21L3 16.5m0 0L7.5 12M3 16.5h13.5m0-13.5L21 7.5m0 0L16.5 12M21 7.5H7.5" />
    </IconChip>
  )
}

export function ComplianceIcon() {
  return (
    <IconChip>
      <path d="M9 12.75 11.25 15 15 9.75m-3-7.036A11.959 11.959 0 0 1 3.598 6 11.99 11.99 0 0 0 3 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285Z" />
    </IconChip>
  )
}

export function SourcesIcon() {
  // Database cylinder — matches the sidebar nav icon (ICON_DATABASE) and the
  // EmptySourcesState glyph so the same identity carries across surfaces.
  return (
    <IconChip>
      <path d="M4 7v10c0 2.21 3.58 4 8 4s8-1.79 8-4V7M4 7c0 2.21 3.58 4 8 4s8-1.79 8-4M4 7c0-2.21 3.58-4 8-4s8 1.79 8 4" />
    </IconChip>
  )
}

export function InsightsIcon() {
  return (
    <IconChip>
      <path d="M3 13.125C3 12.504 3.504 12 4.125 12h2.25c.621 0 1.125.504 1.125 1.125v6.75C7.5 20.496 6.996 21 6.375 21h-2.25A1.125 1.125 0 0 1 3 19.875v-6.75ZM9.75 8.625c0-.621.504-1.125 1.125-1.125h2.25c.621 0 1.125.504 1.125 1.125v11.25c0 .621-.504 1.125-1.125 1.125h-2.25a1.125 1.125 0 0 1-1.125-1.125V8.625ZM16.5 4.125c0-.621.504-1.125 1.125-1.125h2.25C20.496 3 21 3.504 21 4.125v15.75c0 .621-.504 1.125-1.125 1.125h-2.25a1.125 1.125 0 0 1-1.125-1.125V4.125Z" />
    </IconChip>
  )
}

export function ActivityIcon() {
  return (
    <IconChip>
      <path d="M12 6v6h4.5m4.5 0a9 9 0 1 1-18 0 9 9 0 0 1 18 0Z" />
    </IconChip>
  )
}

export function InboxIcon() {
  return (
    <IconChip>
      <path d="M3.75 6.75h16.5M3.75 12h16.5m-16.5 5.25h16.5" />
    </IconChip>
  )
}

export function HomeIcon() {
  return (
    <IconChip>
      <path d="m2.25 12 8.954-8.955c.44-.439 1.152-.439 1.591 0L21.75 12M4.5 9.75v10.125c0 .621.504 1.125 1.125 1.125H9.75v-4.875c0-.621.504-1.125 1.125-1.125h2.25c.621 0 1.125.504 1.125 1.125V21h4.125c.621 0 1.125-.504 1.125-1.125V9.75M8.25 21h8.25" />
    </IconChip>
  )
}

export function PostureIcon() {
  return (
    <IconChip>
      <path d="M12 9v3.75m0-10.036A11.959 11.959 0 0 1 3.598 6 11.99 11.99 0 0 0 3 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285ZM12 15.75h.007v.008H12v-.008Z" />
    </IconChip>
  )
}

export function ReportsIcon() {
  return (
    <IconChip>
      <path d="M9 12h6M9 15h4M7.5 3.75H6a2.25 2.25 0 0 0-2.25 2.25v13.5A2.25 2.25 0 0 0 6 21.75h12A2.25 2.25 0 0 0 20.25 19.5V6a2.25 2.25 0 0 0-2.25-2.25h-1.5M9 3.75h6M9 3.75a.75.75 0 0 0 0 1.5h6a.75.75 0 0 0 0-1.5H9Z" />
    </IconChip>
  )
}

export function RulesIcon() {
  return (
    <IconChip>
      <path d="M19.5 14.25v-2.625a3.375 3.375 0 0 0-3.375-3.375h-1.5A1.125 1.125 0 0 1 13.5 7.125v-1.5a3.375 3.375 0 0 0-3.375-3.375H8.25m0 12.75h7.5m-7.5 3H12M10.5 2.25H5.625c-.621 0-1.125.504-1.125 1.125v17.25c0 .621.504 1.125 1.125 1.125h12.75c.621 0 1.125-.504 1.125-1.125V11.25a9 9 0 0 0-9-9Z" />
    </IconChip>
  )
}

export function ImagesIcon() {
  return (
    <IconChip>
      <path d="M3.75 6.75A2.25 2.25 0 0 1 6 4.5h12a2.25 2.25 0 0 1 2.25 2.25v10.5A2.25 2.25 0 0 1 18 19.5H6A2.25 2.25 0 0 1 3.75 17.25V6.75ZM3.75 16.5l4.5-4.5 3 3 3-3 6 6m-6-9a1.5 1.5 0 1 1-3 0 1.5 1.5 0 0 1 3 0Z" />
    </IconChip>
  )
}

export function ReleasesIcon() {
  return (
    <IconChip>
      <path d="M9 12.75 11.25 15 15 9.75M3.75 9.75h16.5M3.75 9.75A2.25 2.25 0 0 1 6 7.5h12a2.25 2.25 0 0 1 2.25 2.25v9A2.25 2.25 0 0 1 18 21H6a2.25 2.25 0 0 1-2.25-2.25v-9ZM7.5 7.5V5.25A2.25 2.25 0 0 1 9.75 3h4.5a2.25 2.25 0 0 1 2.25 2.25V7.5" />
    </IconChip>
  )
}

export function CloudIcon() {
  return (
    <IconChip>
      <path d="M2.25 15a4.5 4.5 0 0 0 4.5 4.5H18a3.75 3.75 0 0 0 1.332-7.257 3 3 0 0 0-3.758-3.848 5.25 5.25 0 0 0-10.233 2.33A4.502 4.502 0 0 0 2.25 15Z" />
    </IconChip>
  )
}

export function MembersIcon() {
  return (
    <IconChip>
      <path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2" />
      <circle cx="9" cy="7" r="4" />
      <path d="M22 21v-2a4 4 0 0 0-3-3.87M16 3.13a4 4 0 0 1 0 7.75" />
    </IconChip>
  )
}

export function RolesIcon() {
  return (
    <IconChip>
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
      <path d="m9 12 2 2 4-4" />
    </IconChip>
  )
}

export function IntegrationsIcon() {
  return (
    <IconChip>
      <path d="M12 22v-5" />
      <path d="M9 8V2" />
      <path d="M15 8V2" />
      <path d="M18 8v5a4 4 0 0 1-4 4h-4a4 4 0 0 1-4-4V8Z" />
    </IconChip>
  )
}

export function TeamsIcon() {
  return (
    <IconChip>
      <path d="M17 21v-2a4 4 0 0 0-3-3.87" />
      <path d="M7 21v-2a4 4 0 0 1 3-3.87" />
      <circle cx="12" cy="7" r="4" />
      <path d="M5 11h.01M19 11h.01" />
    </IconChip>
  )
}

export function NotificationsIcon() {
  return (
    <IconChip>
      <path d="M14.857 17.082a23.848 23.848 0 0 0 5.454-1.31A8.967 8.967 0 0 1 18 9.75V9A6 6 0 0 0 6 9v.75a8.967 8.967 0 0 1-2.312 6.022c1.733.64 3.56 1.085 5.455 1.31m5.714 0a24.255 24.255 0 0 1-5.714 0m5.714 0a3 3 0 1 1-5.714 0" />
    </IconChip>
  )
}
