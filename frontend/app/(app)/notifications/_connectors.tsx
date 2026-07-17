"use client"

import { useState } from "react"
import Link from "next/link"

import { createDestination, type NotificationDestination } from "@/lib/client/destinations-api"
import { type ConnectorType } from "@/lib/client/integrations-catalog-api"
import { Modal } from "@/app/(app)/settings/account/Modal"
import { Button } from "@/components/ui/Button"
import { Input } from "@/components/ui/Input"
import { Select } from "@/components/ui/Select"

const ORG_ID = process.env.NEXT_PUBLIC_ORG_ID ?? "example-org"

// FE-only roadmap placeholders — surfaced as disabled "Coming soon" cards
// alongside live catalog entries. Adding a connector to the live backend
// catalog automatically removes the matching placeholder via id collision.
export const COMING_SOON_CONNECTORS: ConnectorType[] = [
  {
    id: "discord",
    name: "Discord",
    description: "Webhook-based posts to Discord servers.",
    category: "notifications",
    icon_slug: "discord",
    enterprise_only: false,
    config_fields: [],
    docs_url: "",
    version: "",
    status: "preview",
    href: null,
    coming_soon: true,
  },
  {
    id: "datadog",
    name: "Datadog",
    description: "Forward findings as events tagged for dashboards and monitors.",
    category: "notifications",
    icon_slug: "datadog",
    enterprise_only: true,
    config_fields: [],
    docs_url: "",
    version: "",
    status: "preview",
    href: null,
    coming_soon: true,
  },
  {
    id: "servicenow",
    name: "ServiceNow",
    description: "Create incidents in Security Incident Response (SIR).",
    category: "ticketing",
    icon_slug: "servicenow",
    enterprise_only: true,
    config_fields: [],
    docs_url: "",
    version: "",
    status: "preview",
    href: null,
    coming_soon: true,
  },
  {
    id: "bitbucket_pipelines",
    name: "Bitbucket Pipelines",
    description: "Trigger Bitbucket pipelines on scan completion.",
    category: "cicd",
    icon_slug: "bitbucket",
    enterprise_only: true,
    config_fields: [],
    docs_url: "",
    version: "",
    status: "preview",
    href: null,
    coming_soon: true,
  },
]

export const CATEGORY_ORDER = ["notifications", "ticketing", "cicd", "automation"]
export const CATEGORY_DISPLAY: Record<string, string> = {
  notifications: "Notifications",
  ticketing: "Ticketing",
  cicd: "CI/CD",
  automation: "Automation",
}

// ---------------------------------------------------------------------------
// ConnectorCard
// ---------------------------------------------------------------------------

export function ConnectorCard({
  connector,
  configured,
  canConfigure,
  onConfigure,
}: {
  connector: ConnectorType
  configured: boolean
  canConfigure: boolean
  onConfigure: () => void
}) {
  const isApiKeys = connector.id === "api_keys"
  const isComingSoon = connector.coming_soon === true

  const cardClass = isComingSoon
    ? "group relative rounded-md border border-[var(--color-border)] bg-[var(--color-surface)] p-5 opacity-60 cursor-not-allowed"
    : "group relative rounded-md border border-[var(--color-border)] bg-[var(--color-surface)] p-5 transition-colors hover:border-[var(--color-accent)]/30 hover:bg-[var(--color-surface-raised)]"

  return (
    <div className={cardClass} aria-disabled={isComingSoon || undefined}>
      <div className="flex items-start gap-3">
        <div className="shrink-0">{ICON_FOR_SLUG[connector.icon_slug] ?? <DefaultIcon />}</div>
        <div className="min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <p className="text-sm font-semibold text-[var(--color-text-primary)]">{connector.name}</p>
            {isComingSoon && (
              <span className="rounded-full bg-[var(--color-surface-raised)] px-2 py-0.5 text-2xs font-semibold uppercase tracking-[0.14em] text-[var(--color-text-tertiary)]">
                Soon
              </span>
            )}
            {!isComingSoon && configured && (
              <span className="rounded-full bg-[var(--color-status-ok)]/15 px-2 py-px text-2xs font-semibold text-[var(--color-status-ok)]">
                Connected
              </span>
            )}
            {!isComingSoon && !canConfigure && (
              <span className="rounded-full bg-[var(--color-state-dismissed-subtle)] px-2 py-px text-2xs font-semibold text-[var(--color-state-dismissed)]">
                Enterprise
              </span>
            )}
          </div>
          <p className="mt-1.5 text-xs leading-relaxed text-[var(--color-text-secondary)]">
            {connector.description}
          </p>
        </div>
      </div>

      {isComingSoon ? (
        <div className="mt-4">
          <Button variant="secondary" size="sm" disabled className="w-full">
            Coming soon
          </Button>
        </div>
      ) : isApiKeys ? (
        <Link href="/settings/api-keys" className="mt-4 block">
          <Button variant="secondary" size="sm" className="w-full border-[var(--color-accent)] text-[var(--color-accent)]">
            Manage API keys →
          </Button>
        </Link>
      ) : (
        <div className="mt-4">
          <Button
            variant="secondary"
            size="sm"
            onClick={onConfigure}
            disabled={!canConfigure}
            className="w-full"
          >
            {configured ? "Add another" : "Configure"}
          </Button>
        </div>
      )}
    </div>
  )
}

// ---------------------------------------------------------------------------
// CatalogConnectorModal — catalog-driven config form
// ---------------------------------------------------------------------------

export function CatalogConnectorModal({
  connector,
  onClose,
  onSaved,
}: {
  connector: ConnectorType
  onClose: () => void
  onSaved: (dest: NotificationDestination) => void
}) {
  const [name, setName] = useState(connector.name)
  const [fieldValues, setFieldValues] = useState<Record<string, string>>(() =>
    Object.fromEntries(connector.config_fields.map((f) => [f.name, ""]))
  )
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const labelClass =
    "block text-[11px] font-semibold uppercase tracking-[0.22em] text-[var(--color-text-secondary)] mb-1.5"

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    setSubmitting(true)
    setError(null)
    try {
      const dest = await createDestination({
        destination_type: connector.id,
        name,
        config: fieldValues,
      })
      onSaved(dest)
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Failed to create destination")
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <Modal open={true} title={`Configure ${connector.name}`} onClose={onClose}>
      <form onSubmit={(e) => { void handleSubmit(e) }} className="space-y-4">
        {error && (
          <p className="text-sm text-[var(--color-severity-critical)]">{error}</p>
        )}

        <div>
          <label htmlFor="modal-dest-name" className={labelClass}>
            Destination name
          </label>
          <Input
            id="modal-dest-name"
            type="text"
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder={`e.g. ${connector.name} alerts`}
            required
          />
        </div>

        {connector.config_fields.map((field) => (
          <div key={field.name}>
            <label htmlFor={`modal-field-${field.name}`} className={labelClass}>
              {field.label}
              {!field.required && (
                <span className="ml-1 font-normal normal-case text-[var(--color-text-tertiary)]">
                  (optional)
                </span>
              )}
            </label>
            {field.field_type === "select" ? (
              <Select
                id={`modal-field-${field.name}`}
                value={fieldValues[field.name] ?? ""}
                onChange={(e) =>
                  setFieldValues((prev) => ({ ...prev, [field.name]: e.target.value }))
                }
                required={field.required}
              >
                <option value="">Select…</option>
                {(field.options ?? []).map((opt) => (
                  <option key={opt} value={opt}>
                    {opt}
                  </option>
                ))}
              </Select>
            ) : (
              <Input
                id={`modal-field-${field.name}`}
                type={field.field_type === "password" ? "password" : field.field_type === "url" ? "url" : "text"}
                value={fieldValues[field.name] ?? ""}
                onChange={(e) =>
                  setFieldValues((prev) => ({ ...prev, [field.name]: e.target.value }))
                }
                placeholder={field.placeholder ?? ""}
                required={field.required}
                autoComplete={field.field_type === "password" ? "new-password" : "off"}
              />
            )}
          </div>
        ))}

        <div className="flex items-center justify-end gap-2 border-t border-[var(--color-border)] pt-4">
          <Button variant="secondary" size="md" onClick={onClose} disabled={submitting}>
            Cancel
          </Button>
          <Button type="submit" variant="primary" size="md" disabled={submitting} isLoading={submitting}>
            {submitting ? "Saving…" : "Save"}
          </Button>
        </div>
      </form>
    </Modal>
  )
}

// ---------------------------------------------------------------------------
// Icon slug → JSX map — slugs matched to backend catalog.py icon_slug values
// ---------------------------------------------------------------------------

const ICON_FOR_SLUG: Record<string, React.ReactNode> = {
  slack: <SlackIcon />,
  microsoft_teams: <TeamsIcon />,
  pagerduty: <PagerDutyIcon />,
  email: <EmailIcon />,
  jira: <JiraIcon />,
  linear: <LinearIcon />,
  github: <GitHubIcon />,
  gitlab: <GitLabIcon />,
  jenkins: <JenkinsIcon />,
  webhook: <WebhookIcon />,
  key: <ApiKeyIcon />,
  discord: <DiscordIcon />,
  datadog: <DatadogIcon />,
  servicenow: <ServiceNowIcon />,
  bitbucket: <BitbucketIcon />,
}

function IconWrapper({ children, bg }: { children: React.ReactNode; bg: string }) {
  return (
    <div className={`flex h-9 w-9 shrink-0 items-center justify-center rounded-xl ${bg}`}>
      {children}
    </div>
  )
}

function DefaultIcon() {
  return (
    <IconWrapper bg="bg-[var(--color-surface-raised)]">
      <svg
        aria-hidden="true"
        className="h-5 w-5 text-[var(--color-text-tertiary)]"
        viewBox="0 0 24 24"
        fill="none"
        stroke="currentColor"
        strokeWidth={1.5}
        strokeLinecap="round"
        strokeLinejoin="round"
      >
        <path d="M14.25 6.087c0-.355.186-.676.401-.959.221-.29.349-.634.349-1.003 0-1.036-1.007-1.875-2.25-1.875s-2.25.84-2.25 1.875c0 .369.128.713.349 1.003.215.283.401.604.401.959v0a.64.64 0 0 1-.657.643 48.39 48.39 0 0 1-4.163-.3c.186 1.613.293 3.25.315 4.907a.656.656 0 0 1-.658.663v0c-.355 0-.676-.186-.959-.401a1.647 1.647 0 0 0-1.003-.349c-1.036 0-1.875 1.007-1.875 2.25s.84 2.25 1.875 2.25c.369 0 .713-.128 1.003-.349.283-.215.604-.401.959-.401v0c.31 0 .555.26.532.57a48.039 48.039 0 0 1-.642 5.056c1.518.19 3.058.309 4.616.354a.64.64 0 0 0 .657-.643v0c0-.355-.186-.676-.401-.959a1.647 1.647 0 0 1-.349-1.003c0-1.035 1.008-1.875 2.25-1.875 1.243 0 2.25.84 2.25 1.875 0 .369-.128.713-.349 1.003-.215.283-.4.604-.4.959v0c0 .333.277.599.61.58a48.1 48.1 0 0 0 5.427-.63 48.05 48.05 0 0 0 .582-4.717.532.532 0 0 0-.533-.57v0c-.355 0-.676.186-.959.401-.29.221-.634.349-1.003.349-1.035 0-1.875-1.007-1.875-2.25s.84-2.25 1.875-2.25c.37 0 .713.128 1.003.349.283.215.604.4.959.4v0a.656.656 0 0 0 .658-.663 48.422 48.422 0 0 0-.37-5.36c-1.886.342-3.81.574-5.766.689a.578.578 0 0 1-.61-.58v0Z" />
      </svg>
    </IconWrapper>
  )
}

export function IntegrationsIcon() {
  return (
    <div className="p-1.5 rounded-lg bg-[var(--color-accent-subtle)]">
      <svg aria-hidden="true" className="w-5 h-5 text-[var(--color-accent)]" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.5} strokeLinecap="round" strokeLinejoin="round">
        <path d="M13.5 16.875h3.375m0 0h3.375m-3.375 0V13.5m0 3.375v3.375M6 10.5h2.25a2.25 2.25 0 0 0 2.25-2.25V6a2.25 2.25 0 0 0-2.25-2.25H6A2.25 2.25 0 0 0 3.75 6v2.25A2.25 2.25 0 0 0 6 10.5Zm0 9.75h2.25A2.25 2.25 0 0 0 10.5 18v-2.25a2.25 2.25 0 0 0-2.25-2.25H6a2.25 2.25 0 0 0-2.25 2.25V18A2.25 2.25 0 0 0 6 20.25Zm9.75-9.75H18a2.25 2.25 0 0 0 2.25-2.25V6A2.25 2.25 0 0 0 18 3.75h-2.25A2.25 2.25 0 0 0 13.5 6v2.25a2.25 2.25 0 0 0 2.25 2.25Z" />
      </svg>
    </div>
  )
}

function SlackIcon() {
  return (
    <IconWrapper bg="bg-[#E01E5A]/10">
      <svg aria-hidden="true" className="h-5 w-5 text-[#E01E5A]" viewBox="0 0 24 24" fill="currentColor">
        <path d="M5.042 15.165a2.528 2.528 0 0 1-2.52 2.523A2.528 2.528 0 0 1 0 15.165a2.527 2.527 0 0 1 2.522-2.52h2.52v2.52zm1.271 0a2.527 2.527 0 0 1 2.521-2.52 2.527 2.527 0 0 1 2.521 2.52v6.313A2.528 2.528 0 0 1 8.834 24a2.528 2.528 0 0 1-2.521-2.522v-6.313zM8.834 5.042a2.528 2.528 0 0 1-2.521-2.52A2.528 2.528 0 0 1 8.834 0a2.528 2.528 0 0 1 2.521 2.522v2.52H8.834zm0 1.271a2.528 2.528 0 0 1 2.521 2.521 2.528 2.528 0 0 1-2.521 2.521H2.522A2.528 2.528 0 0 1 0 8.834a2.528 2.528 0 0 1 2.522-2.521h6.312zM18.956 8.834a2.528 2.528 0 0 1 2.522-2.521A2.528 2.528 0 0 1 24 8.834a2.528 2.528 0 0 1-2.522 2.521h-2.522V8.834zm-1.27 0a2.528 2.528 0 0 1-2.523 2.521 2.527 2.527 0 0 1-2.52-2.521V2.522A2.527 2.527 0 0 1 15.163 0a2.528 2.528 0 0 1 2.523 2.522v6.312zM15.163 18.956a2.528 2.528 0 0 1 2.523 2.522A2.528 2.528 0 0 1 15.163 24a2.527 2.527 0 0 1-2.52-2.522v-2.522h2.52zm0-1.27a2.527 2.527 0 0 1-2.52-2.523 2.527 2.527 0 0 1 2.52-2.52h6.315A2.528 2.528 0 0 1 24 15.163a2.528 2.528 0 0 1-2.522 2.523h-6.315z" />
      </svg>
    </IconWrapper>
  )
}

function TeamsIcon() {
  return (
    <IconWrapper bg="bg-[#6264A7]/10">
      <svg aria-hidden="true" className="h-5 w-5 text-[#6264A7]" viewBox="0 0 24 24" fill="currentColor">
        <path d="M20.625 8.25h-3.375v6.375a3.375 3.375 0 0 1-6.75 0V7.5H3.375A1.875 1.875 0 0 0 1.5 9.375v7.5a1.875 1.875 0 0 0 1.875 1.875h4.313L9 22.5l1.313-3.75h4.312a1.875 1.875 0 0 0 1.875-1.875V15h4.125A1.875 1.875 0 0 0 22.5 13.125v-3A1.875 1.875 0 0 0 20.625 8.25zM18 6a2.25 2.25 0 1 0 0-4.5A2.25 2.25 0 0 0 18 6zM9.75 6a3 3 0 1 0 0-6 3 3 0 0 0 0 6z" />
      </svg>
    </IconWrapper>
  )
}

function PagerDutyIcon() {
  return (
    <IconWrapper bg="bg-[#06AC38]/10">
      <svg aria-hidden="true" className="h-5 w-5 text-[#06AC38]" viewBox="0 0 24 24" fill="currentColor">
        <path d="M12.006 0C5.391 0 1.127 3.6 1.127 9.166c0 5.185 3.736 8.669 9.674 8.669h1.205V24h3.263V0h-3.263zm-.076 14.783c-3.736 0-6.24-2.29-6.24-5.735 0-3.672 2.504-6.013 6.316-6.013h3.263v11.748h-3.339z" />
      </svg>
    </IconWrapper>
  )
}

function JiraIcon() {
  return (
    <IconWrapper bg="bg-[#0052CC]/10">
      <svg aria-hidden="true" className="h-5 w-5 text-[#0052CC]" viewBox="0 0 24 24" fill="currentColor">
        <path d="M11.571 11.513H0a5.218 5.218 0 0 0 5.232 5.215h2.13v2.057A5.215 5.215 0 0 0 12.575 24V12.518a1.005 1.005 0 0 0-1.005-1.005zm5.723-5.756H5.736a5.215 5.215 0 0 0 5.215 5.214h2.129v2.058a5.218 5.218 0 0 0 5.215 5.214V6.758a1.001 1.001 0 0 0-1.001-1.001zM23 0H11.443a5.217 5.217 0 0 0 5.214 5.217h2.129v2.058A5.218 5.218 0 0 0 24 12.49V1.005A1.005 1.005 0 0 0 23 0z" />
      </svg>
    </IconWrapper>
  )
}

function LinearIcon() {
  return (
    <IconWrapper bg="bg-[#5E6AD2]/10">
      <svg aria-hidden="true" className="h-5 w-5 text-[#5E6AD2]" viewBox="0 0 24 24" fill="currentColor">
        <path d="M2.652 15.555a.5.5 0 0 1-.048-.592C4.239 12.064 7.086 9.99 12 9.99s7.761 2.074 9.396 4.973a.5.5 0 0 1-.048.592L12 24 2.652 15.555zM12 0a9 9 0 1 0 0 18A9 9 0 0 0 12 0z" />
      </svg>
    </IconWrapper>
  )
}

function GitHubIcon() {
  return (
    <IconWrapper bg="bg-[var(--color-surface-raised)]">
      <svg aria-hidden="true" className="h-5 w-5 text-[var(--color-text-primary)]" viewBox="0 0 24 24" fill="currentColor">
        <path d="M12 .297c-6.63 0-12 5.373-12 12 0 5.303 3.438 9.8 8.205 11.385.6.113.82-.258.82-.577 0-.285-.01-1.04-.015-2.04-3.338.724-4.042-1.61-4.042-1.61C4.422 18.07 3.633 17.7 3.633 17.7c-1.087-.744.084-.729.084-.729 1.205.084 1.838 1.236 1.838 1.236 1.07 1.835 2.809 1.305 3.495.998.108-.776.417-1.305.76-1.605-2.665-.3-5.466-1.332-5.466-5.93 0-1.31.465-2.38 1.235-3.22-.135-.303-.54-1.523.105-3.176 0 0 1.005-.322 3.3 1.23.96-.267 1.98-.399 3-.405 1.02.006 2.04.138 3 .405 2.28-1.552 3.285-1.23 3.285-1.23.645 1.653.24 2.873.12 3.176.765.84 1.23 1.91 1.23 3.22 0 4.61-2.805 5.625-5.475 5.92.42.36.81 1.096.81 2.22 0 1.606-.015 2.896-.015 3.286 0 .315.21.69.825.57C20.565 22.092 24 17.592 24 12.297c0-6.627-5.373-12-12-12" />
      </svg>
    </IconWrapper>
  )
}

function GitLabIcon() {
  return (
    <IconWrapper bg="bg-[#FC6D26]/10">
      <svg aria-hidden="true" className="h-5 w-5 text-[#FC6D26]" viewBox="0 0 24 24" fill="currentColor">
        <path d="m23.6 9.593-1.637-5.037a.376.376 0 0 0-.02-.058L20.3.907a.757.757 0 0 0-1.439.038l-1.563 4.795H6.702L5.14.945a.757.757 0 0 0-1.44-.038L2.057 4.498a.387.387 0 0 0-.02.058L.4 9.593a1.088 1.088 0 0 0 .393 1.216l11.073 8.044a.193.193 0 0 0 .228 0l11.073-8.044a1.088 1.088 0 0 0 .394-1.216" />
      </svg>
    </IconWrapper>
  )
}

function JenkinsIcon() {
  return (
    <IconWrapper bg="bg-[#D33833]/10">
      <svg aria-hidden="true" className="h-5 w-5 text-[#D33833]" viewBox="0 0 24 24" fill="currentColor">
        <path d="M5.566 9.157a.455.455 0 1 1 .909 0 .455.455 0 0 1-.909 0zm7.783-1.59a5.869 5.869 0 0 1 4.485 2.063 5.878 5.878 0 0 1 1.321 4.903A5.881 5.881 0 0 1 6.078 16.6a5.881 5.881 0 0 1 7.271-9.034zM12 0C5.373 0 0 5.373 0 12s5.373 12 12 12 12-5.373 12-12S18.627 0 12 0z" />
      </svg>
    </IconWrapper>
  )
}

function WebhookIcon() {
  return (
    <IconWrapper bg="bg-[var(--color-surface-raised)]">
      <svg aria-hidden="true" className="h-5 w-5 text-[var(--color-text-secondary)]" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.5} strokeLinecap="round" strokeLinejoin="round">
        <path d="M10.5 6h9.75M10.5 6a1.5 1.5 0 1 1-3 0m3 0a1.5 1.5 0 1 0-3 0M3.75 6H7.5m3 12h9.75m-9.75 0a1.5 1.5 0 0 1-3 0m3 0a1.5 1.5 0 0 0-3 0m-3.75 0H7.5m9-6h3.75m-3.75 0a1.5 1.5 0 0 1-3 0m3 0a1.5 1.5 0 0 0-3 0m-9.75 0h9.75" />
      </svg>
    </IconWrapper>
  )
}

function ApiKeyIcon() {
  return (
    <IconWrapper bg="bg-[var(--color-surface-raised)]">
      <svg aria-hidden="true" className="h-5 w-5 text-[var(--color-text-secondary)]" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.5} strokeLinecap="round" strokeLinejoin="round">
        <path d="M15.75 5.25a3 3 0 0 1 3 3m3 0a6 6 0 0 1-7.029 5.912c-.563-.097-1.159.026-1.563.43L10.5 17.25H8.25v2.25H6v2.25H2.25v-2.818c0-.597.237-1.17.659-1.591l6.499-6.499c.404-.404.527-1 .43-1.563A6 6 0 1 1 21.75 8.25Z" />
      </svg>
    </IconWrapper>
  )
}

function EmailIcon() {
  return (
    <IconWrapper bg="bg-[var(--color-surface-raised)]">
      <svg aria-hidden="true" className="h-5 w-5 text-[var(--color-text-secondary)]" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.5} strokeLinecap="round" strokeLinejoin="round">
        <path d="M21.75 6.75v10.5a2.25 2.25 0 0 1-2.25 2.25h-15a2.25 2.25 0 0 1-2.25-2.25V6.75m19.5 0A2.25 2.25 0 0 0 19.5 4.5h-15a2.25 2.25 0 0 0-2.25 2.25m19.5 0v.243a2.25 2.25 0 0 1-1.07 1.916l-7.5 4.615a2.25 2.25 0 0 1-2.36 0L3.32 8.91a2.25 2.25 0 0 1-1.07-1.916V6.75" />
      </svg>
    </IconWrapper>
  )
}

function DiscordIcon() {
  return (
    <IconWrapper bg="bg-[#5865F2]/10">
      <svg aria-hidden="true" className="h-5 w-5 text-[#5865F2]" viewBox="0 0 24 24" fill="currentColor">
        <path d="M19.27 5.33C17.94 4.71 16.5 4.26 15 4a.09.09 0 0 0-.07.03c-.18.33-.39.76-.53 1.09-1.6-.24-3.2-.24-4.8 0-.14-.34-.35-.76-.54-1.09-.01-.02-.04-.03-.07-.03-1.5.26-2.93.71-4.27 1.33-.01 0-.02.01-.03.02C2.07 9.46 1.32 13.5 1.69 17.48c0 .02.01.04.03.05 1.8 1.32 3.53 2.12 5.24 2.65.03.01.06 0 .07-.02.4-.55.76-1.13 1.07-1.74.02-.04 0-.08-.04-.09-.57-.22-1.11-.48-1.64-.78-.04-.02-.04-.08-.01-.11.11-.08.22-.17.33-.25.02-.02.05-.02.07-.01 3.44 1.57 7.15 1.57 10.55 0 .02-.01.05-.01.07.01.11.09.22.17.33.26.04.03.04.09-.01.11-.52.31-1.07.56-1.64.78-.04.01-.05.06-.04.09.32.61.68 1.19 1.07 1.74.03.01.06.02.09.01 1.72-.53 3.45-1.33 5.25-2.65.02-.01.03-.03.03-.05.44-4.6-.73-8.6-3.1-12.13-.01-.01-.02-.02-.04-.02zM8.52 15.09c-1.03 0-1.89-.95-1.89-2.12s.84-2.12 1.89-2.12c1.06 0 1.9.96 1.89 2.12 0 1.17-.84 2.12-1.89 2.12zm6.97 0c-1.03 0-1.89-.95-1.89-2.12s.84-2.12 1.89-2.12c1.06 0 1.9.96 1.89 2.12 0 1.17-.83 2.12-1.89 2.12z" />
      </svg>
    </IconWrapper>
  )
}

function DatadogIcon() {
  return (
    <IconWrapper bg="bg-[#632CA6]/10">
      <svg aria-hidden="true" className="h-5 w-5 text-[#632CA6]" viewBox="0 0 24 24" fill="currentColor">
        <path d="M22 5.7L17.4 9.5l-3.4-4.8L8 8l-3.4-3.3L2 6.6v11.7l4-2.4 3.4 3.5 5.4-3.2 3.4 3.4L22 17V5.7z" />
      </svg>
    </IconWrapper>
  )
}

function ServiceNowIcon() {
  return (
    <IconWrapper bg="bg-[#62D84E]/10">
      <svg aria-hidden="true" className="h-5 w-5 text-[#62D84E]" viewBox="0 0 24 24" fill="currentColor">
        <circle cx="12" cy="12" r="11" />
        <path d="M12 6.5c-3.04 0-5.5 2.46-5.5 5.5s2.46 5.5 5.5 5.5 5.5-2.46 5.5-5.5-2.46-5.5-5.5-5.5zm0 9c-1.93 0-3.5-1.57-3.5-3.5s1.57-3.5 3.5-3.5 3.5 1.57 3.5 3.5-1.57 3.5-3.5 3.5z" fill="#0a0d12" />
      </svg>
    </IconWrapper>
  )
}

function BitbucketIcon() {
  return (
    <IconWrapper bg="bg-[#0052CC]/10">
      <svg aria-hidden="true" className="h-5 w-5 text-[#0052CC]" viewBox="0 0 24 24" fill="currentColor">
        <path d="M.778 1.213a.768.768 0 0 0-.768.892l3.263 19.81c.084.5.515.868 1.022.873H19.95a.772.772 0 0 0 .77-.646l3.27-20.03a.768.768 0 0 0-.768-.891H.778zm14.41 14.45H8.804L7.13 8.92h9.74l-1.681 6.743z" />
      </svg>
    </IconWrapper>
  )
}
