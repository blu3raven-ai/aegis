"use client"

import { useEffect, useMemo, useState } from "react"

import { SettingsCard } from "@/components/settings/SettingsCard"
import { SettingsRow } from "@/components/settings/SettingsRow"
import { SettingsSection } from "@/components/settings/SettingsSection"
import { useLicense } from "@/lib/client/license/client"

const TIME_ZONES = [
  "Asia/Kuala_Lumpur",
  "Asia/Singapore",
  "Asia/Tokyo",
  "America/Los_Angeles",
  "America/New_York",
  "Europe/London",
  "Europe/Berlin",
  "Pacific/Auckland",
  "UTC",
]

const RESIDENCY = ["US (us-east-1)", "EU (eu-west-1)", "APAC (ap-southeast-1)"]

function slugify(value: string): string {
  return value
    .toLowerCase()
    .trim()
    .replace(/[^a-z0-9\s-]/g, "")
    .replace(/\s+/g, "-")
    .replace(/-+/g, "-")
    .replace(/^-+|-+$/g, "")
}

export function OrgGeneralSection() {
  const { license, isLoading } = useLicense()
  const licenseOrg = license?.org ?? ""

  const [name, setName] = useState("")
  const [slug, setSlug] = useState("")
  const [timezone, setTimezone] = useState("")
  const [residency, setResidency] = useState(RESIDENCY[0])
  const [contactEmail, setContactEmail] = useState("")

  // Hydrate the org-identity fields once the license response lands. The
  // residency / contact fields stay empty until a real backend supplies them.
  useEffect(() => {
    if (licenseOrg) {
      setName(licenseOrg)
      setSlug(slugify(licenseOrg))
    }
  }, [licenseOrg])

  useEffect(() => {
    const detected = Intl.DateTimeFormat().resolvedOptions().timeZone ?? "UTC"
    setTimezone(detected)
  }, [])

  const initials = useMemo(() => {
    const seed = name.trim() || "Org"
    return seed.slice(0, 2).toUpperCase()
  }, [name])

  const zoneOptions = timezone && !TIME_ZONES.includes(timezone)
    ? [timezone, ...TIME_ZONES]
    : TIME_ZONES

  return (
    <SettingsSection
      id="general"
      title="General"
      subtitle="Organization identity, defaults, and data residency"
    >
      <SettingsCard heading="Identity">
        <SettingsRow
          label="Organization name"
          description={
            isLoading
              ? "Loading…"
              : licenseOrg
                ? "How members see this org in the sidebar"
                : "No license registered — activate one under License to populate this row"
          }
          layout="stack"
        >
          <input
            aria-label="Organization name"
            placeholder="Organization name"
            className={inputClass}
            value={name}
            onChange={(e) => setName(e.target.value)}
          />
        </SettingsRow>
        <SettingsRow
          label="Slug"
          description="URL identifier — lowercase, dashes only. Changing it breaks share links."
          layout="stack"
        >
          <div className="flex items-center gap-2">
            <span className="shrink-0 text-xs text-[var(--color-text-tertiary)]">
              aegis.com /
            </span>
            <input
              aria-label="Slug"
              placeholder="your-org"
              className={inputClass}
              value={slug}
              onChange={(e) =>
                setSlug(e.target.value.toLowerCase().replace(/[^a-z0-9-]/g, ""))
              }
            />
          </div>
        </SettingsRow>
        <SettingsRow label="Logo" description="PNG/SVG · max 2MB · square">
          <div
            aria-hidden="true"
            className="grid h-9 w-9 shrink-0 place-items-center rounded-md bg-gradient-to-br from-[var(--color-accent)] to-[#8b5cf6] text-xs font-bold text-white"
          >
            {initials}
          </div>
          <button type="button" className={btnClass}>
            Upload
          </button>
        </SettingsRow>
      </SettingsCard>

      <SettingsCard heading="Defaults">
        <SettingsRow
          label="Default time zone"
          description="Used for digests, scheduled reports, and SLA cut-offs"
        >
          <select
            aria-label="Default time zone"
            className={selectClass}
            value={timezone}
            onChange={(e) => setTimezone(e.target.value)}
          >
            {zoneOptions.map((tz) => (
              <option key={tz} value={tz}>
                {tz}
              </option>
            ))}
          </select>
        </SettingsRow>
        <SettingsRow
          label="Data residency"
          description="Region where SBOMs, scans, and findings are stored. Locked after the first scan."
        >
          <select
            aria-label="Data residency"
            className={selectClass}
            value={residency}
            onChange={(e) => setResidency(e.target.value)}
          >
            {RESIDENCY.map((r) => (
              <option key={r}>{r}</option>
            ))}
          </select>
        </SettingsRow>
        <SettingsRow
          label="Security contact"
          description="Address shown on vulnerability disclosures"
          layout="stack"
        >
          <input
            aria-label="Security contact email"
            type="email"
            placeholder="security@your-org.com"
            className={inputClass}
            value={contactEmail}
            onChange={(e) => setContactEmail(e.target.value)}
          />
        </SettingsRow>
      </SettingsCard>
    </SettingsSection>
  )
}

const inputClass =
  "w-full rounded-md border border-[var(--color-border-strong)] bg-[var(--color-bg)] px-3 py-2 text-sm text-[var(--color-text-primary)] outline-none placeholder:text-[var(--color-text-tertiary)] focus:border-[var(--color-accent)]"

const selectClass =
  "appearance-none rounded-md border border-[var(--color-border-strong)] bg-[var(--color-bg)] px-3 py-1.5 text-sm text-[var(--color-text-primary)] outline-none focus:border-[var(--color-accent)]"

const btnClass =
  "inline-flex items-center gap-1.5 rounded-md border border-[var(--color-border-strong)] bg-[var(--color-surface-2)] px-3 py-1.5 text-xs font-medium text-[var(--color-text-primary)] hover:border-[var(--color-accent)]"
