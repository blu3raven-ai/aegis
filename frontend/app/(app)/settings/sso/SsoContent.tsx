"use client"

import { useState } from "react"

import { SettingsCard } from "@/components/settings/SettingsCard"
import { SettingsRow } from "@/components/settings/SettingsRow"
import { ToggleSwitch } from "@/components/settings/ToggleSwitch"

const PROVIDERS = [
  "Google Workspace",
  "Microsoft Entra ID",
  "Okta",
  "OneLogin",
  "JumpCloud",
  "SAML 2.0 (generic)",
]

/**
 * Full SSO/SAML configuration surface. No tier gating right now — the panel
 * renders for every org so admins can wire up identity providers regardless
 * of plan.
 */
export function SsoContent() {
  const [provider, setProvider] = useState(PROVIDERS[0])
  // SCIM defaults to off until the backend confirms a sync is configured —
  // we don't want to mis-imply provisioning when nothing's wired up yet.
  const [scim, setScim] = useState(false)
  const [streamUrl, setStreamUrl] = useState("")

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-3.5 rounded-xl border border-[var(--color-success)]/30 bg-[var(--color-success-bg)] p-4">
        <span
          aria-hidden="true"
          className="grid h-9 w-9 shrink-0 place-items-center rounded-lg bg-[var(--color-success)] text-white"
        >
          <svg
            className="h-4 w-4"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth={2.5}
            strokeLinecap="round"
            strokeLinejoin="round"
          >
            <path d="m5 12 5 5L20 7" />
          </svg>
        </span>
        <div className="flex-1">
          <div className="text-sm font-semibold text-[var(--color-text-primary)]">
            SSO is enforced for your organization
          </div>
          <div className="mt-0.5 text-xs text-[var(--color-text-secondary)]">
            All members must sign in via the identity provider configured below
          </div>
        </div>
      </div>

      <SettingsCard>
        <SettingsRow
          label="Identity provider"
          description="Where members authenticate"
        >
          <select
            aria-label="Identity provider"
            value={provider}
            onChange={(e) => setProvider(e.target.value)}
            className="appearance-none rounded-md border border-[var(--color-border-strong)] bg-[var(--color-bg)] px-3 py-1.5 text-sm text-[var(--color-text-primary)] outline-none focus:border-[var(--color-accent)]"
          >
            {PROVIDERS.map((p) => (
              <option key={p}>{p}</option>
            ))}
          </select>
        </SettingsRow>

        <SettingsRow
          label="SCIM provisioning"
          description={
            scim
              ? "Last sync: just now · 0 errors"
              : "Members must be added manually in this org"
          }
        >
          <span className="text-xs text-[var(--color-text-tertiary)]">
            {scim ? "Enabled" : "Disabled"}
          </span>
          <ToggleSwitch
            label="Toggle SCIM provisioning"
            checked={scim}
            onChange={setScim}
          />
        </SettingsRow>

        <SettingsRow
          label="Audit log streaming"
          description="Forward audit events to your SIEM. Leave blank to keep events in-app only."
          layout="stack"
        >
          <input
            aria-label="Audit log streaming URL"
            type="url"
            placeholder="https://splunk.example.com/aegis/audit"
            value={streamUrl}
            onChange={(e) => setStreamUrl(e.target.value)}
            className="w-full rounded-md border border-[var(--color-border-strong)] bg-[var(--color-bg)] px-3 py-2 font-mono text-xs text-[var(--color-text-primary)] outline-none focus:border-[var(--color-accent)]"
          />
        </SettingsRow>
      </SettingsCard>
    </div>
  )
}
