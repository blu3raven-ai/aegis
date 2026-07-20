"use client"

import { usePathname } from "next/navigation"

/** Section group each top-level route belongs to — mirrors the sidebar
 *  grouping so the page-header eyebrow reads as `[ Section ]` context. */
const SECTION: Record<string, string> = {
  "": "Overview",
  inbox: "Overview",
  findings: "Overview",
  insights: "Overview",
  activity: "Overview",
  sources: "Inventory",
  sbom: "Inventory",
  chains: "Inventory",
  repos: "Inventory",
  images: "Inventory",
  members: "Workspace",
  roles: "Workspace",
  teams: "Workspace",
  compliance: "Reporting",
  reports: "Reporting",
  posture: "Reporting",
  releases: "Reporting",
  policies: "Configure",
  integrations: "Configure",
  notifications: "Configure",
  settings: "Configure",
  rules: "Configure",
  code: "Scanners",
  containers: "Scanners",
  dependencies: "Scanners",
  iac: "Scanners",
  secrets: "Scanners",
}

/** Mono, bracketed section label rendered above a PageHeader title. */
export function PageEyebrow() {
  const pathname = usePathname() || "/"
  const seg = pathname.split("/").filter(Boolean)[0] ?? ""
  const label = SECTION[seg]
  if (!label) return null
  return (
    <p className="mb-1.5 font-mono text-2xs font-semibold uppercase tracking-[0.18em] text-[var(--color-accent)]">
      <span className="text-[var(--color-text-tertiary)]">[</span> {label}{" "}
      <span className="text-[var(--color-text-tertiary)]">]</span>
    </p>
  )
}
