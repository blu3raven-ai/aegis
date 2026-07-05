"use client"

import { useLicense } from "@/lib/client/license/client"
import { PageHeader } from "@/components/layout/PageHeader"
import Link from "next/link"

interface Integration {
  name: string
  description: string
  icon: React.ReactNode
  category: string
}

const INTEGRATIONS: Integration[] = [
  {
    name: "Slack",
    description: "Route alerts by severity to channels. Critical findings ping on-call instantly.",
    category: "Notifications",
    icon: <SlackIcon />,
  },
  {
    name: "Microsoft Teams",
    description: "Post scan summaries and new finding alerts to Teams channels.",
    category: "Notifications",
    icon: <TeamsIcon />,
  },
  {
    name: "PagerDuty",
    description: "Trigger incidents for critical findings. Auto-resolve when remediated.",
    category: "Notifications",
    icon: <PagerDutyIcon />,
  },
  {
    name: "Jira",
    description: "Create issues from findings. Map severity to priority, track remediation bidirectionally.",
    category: "Ticketing",
    icon: <JiraIcon />,
  },
  {
    name: "Linear",
    description: "Push findings as issues with labels, assignees, and severity mapping.",
    category: "Ticketing",
    icon: <LinearIcon />,
  },
  {
    name: "GitHub Issues",
    description: "Open issues directly from findings. Link back to the scan that found them.",
    category: "Ticketing",
    icon: <GitHubIcon />,
  },
  {
    name: "GitHub Actions",
    description: "Trigger scans from CI pipelines. Fail builds on new critical findings.",
    category: "CI/CD",
    icon: <GitHubActionsIcon />,
  },
  {
    name: "GitLab CI",
    description: "Run scans as pipeline stages. Post results as merge request comments.",
    category: "CI/CD",
    icon: <GitLabIcon />,
  },
  {
    name: "Jenkins",
    description: "Integrate scanning into Jenkins pipelines with build-gating thresholds.",
    category: "CI/CD",
    icon: <JenkinsIcon />,
  },
  {
    name: "Webhooks",
    description: "Send scan events to any endpoint. Retry with exponential backoff, HMAC signatures.",
    category: "Automation",
    icon: <WebhookIcon />,
  },
  {
    name: "API Keys",
    description: "Generate scoped tokens for programmatic access. Per-key permissions and expiry.",
    category: "Automation",
    icon: <ApiKeyIcon />,
  },
  {
    name: "Email Digest",
    description: "Weekly or daily summaries of new findings, remediation progress, and posture changes.",
    category: "Notifications",
    icon: <EmailIcon />,
  },
]

const CATEGORY_ORDER = ["Notifications", "Ticketing", "CI/CD", "Automation"]

function IntegrationsIcon() {
  return (
    <div className="p-1.5 rounded-lg bg-[var(--color-accent-subtle)]">
      <svg className="w-5 h-5 text-[var(--color-accent)]" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.5} strokeLinecap="round" strokeLinejoin="round">
        <path d="M13.5 16.875h3.375m0 0h3.375m-3.375 0V13.5m0 3.375v3.375M6 10.5h2.25a2.25 2.25 0 0 0 2.25-2.25V6a2.25 2.25 0 0 0-2.25-2.25H6A2.25 2.25 0 0 0 3.75 6v2.25A2.25 2.25 0 0 0 6 10.5Zm0 9.75h2.25A2.25 2.25 0 0 0 10.5 18v-2.25a2.25 2.25 0 0 0-2.25-2.25H6a2.25 2.25 0 0 0-2.25 2.25V18A2.25 2.25 0 0 0 6 20.25Zm9.75-9.75H18a2.25 2.25 0 0 0 2.25-2.25V6A2.25 2.25 0 0 0 18 3.75h-2.25A2.25 2.25 0 0 0 13.5 6v2.25a2.25 2.25 0 0 0 2.25 2.25Z" />
      </svg>
    </div>
  )
}

interface IntegrationsContentProps {
  /** When false, suppresses the page header (caller renders its own chrome). */
  showHeader?: boolean
}

export function IntegrationsContent({ showHeader = true }: IntegrationsContentProps = {}) {
  const { tier } = useLicense()
  const isEnterprise = tier === "enterprise"

  return (
    <>
      {showHeader && (
        <PageHeader
          icon={<IntegrationsIcon />}
          title="Integrations"
          description="Connect Aegis to external tools and services"
        />
      )}
      <main className="mx-auto max-w-7xl px-6 py-8 space-y-8">
        {/* Enterprise banner */}
        {!isEnterprise && (
          <div className="flex items-center justify-between rounded-2xl border border-[var(--color-state-dismissed-border)] bg-[var(--color-state-dismissed-subtle)] px-6 py-4">
            <div className="flex items-center gap-3">
              <span className="rounded-full bg-[var(--color-state-dismissed-subtle)] px-2.5 py-0.5 text-xs font-semibold text-[var(--color-state-dismissed)]">
                Enterprise
              </span>
              <p className="text-sm text-[var(--color-text-primary)]">
                Integrations require an Enterprise license. Preview what's coming below.
              </p>
            </div>
            <Link
              href="/settings/license"
              className="shrink-0 rounded-lg border border-[var(--color-state-dismissed-border)] px-4 py-2 text-sm font-semibold text-[var(--color-state-dismissed)] transition-colors hover:bg-[var(--color-state-dismissed-subtle)] focus-visible:ring-2 focus-visible:ring-[var(--color-accent)] focus-visible:outline-none"
            >
              Upgrade
            </Link>
          </div>
        )}

        {/* Integration cards by category */}
        {CATEGORY_ORDER.map((category) => {
          const items = INTEGRATIONS.filter((i) => i.category === category)
          if (!items.length) return null
          return (
            <div key={category}>
              <p className="mb-3 text-[11px] font-semibold uppercase tracking-[0.22em] text-[var(--color-text-tertiary)]">
                {category}
              </p>
              <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
                {items.map((item) => (
                  <div
                    key={item.name}
                    className={`group relative rounded-2xl border border-[var(--color-border)] bg-[var(--color-surface)] p-5 transition-colors ${
                      isEnterprise
                        ? "hover:border-[var(--color-accent)]/30 hover:bg-[var(--color-surface-raised)]"
                        : ""
                    }`}
                  >
                    <div className="flex items-start gap-3">
                      <div className="shrink-0">{item.icon}</div>
                      <div className="min-w-0">
                        <div className="flex items-center gap-2">
                          <p className="text-sm font-semibold text-[var(--color-text-primary)]">
                            {item.name}
                          </p>
                          {isEnterprise ? (
                            <span className="rounded-full bg-[var(--color-state-deferred-subtle)] px-2 py-px text-2xs font-semibold text-[var(--color-state-deferred)]">
                              Coming soon
                            </span>
                          ) : (
                            <span className="rounded-full bg-[var(--color-state-dismissed-subtle)] px-2 py-px text-2xs font-semibold text-[var(--color-state-dismissed)]">
                              Enterprise
                            </span>
                          )}
                        </div>
                        <p className="mt-1.5 text-xs leading-relaxed text-[var(--color-text-secondary)]">
                          {item.description}
                        </p>
                      </div>
                    </div>
                    {isEnterprise && (
                      <button
                        type="button"
                        disabled
                        className="mt-4 w-full rounded-lg border border-[var(--color-border)] py-2 text-xs font-medium text-[var(--color-text-tertiary)] cursor-not-allowed"
                      >
                        Configure
                      </button>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )
        })}
      </main>
    </>
  )
}

// ---------------------------------------------------------------------------
// Integration icons
// ---------------------------------------------------------------------------

function IconWrapper({ children, bg }: { children: React.ReactNode; bg: string }) {
  return (
    <div className={`flex h-9 w-9 shrink-0 items-center justify-center rounded-xl ${bg}`}>
      {children}
    </div>
  )
}

function SlackIcon() {
  return (
    <IconWrapper bg="bg-[#E01E5A]/10">
      <svg className="h-5 w-5 text-[#E01E5A]" viewBox="0 0 24 24" fill="currentColor">
        <path d="M5.042 15.165a2.528 2.528 0 0 1-2.52 2.523A2.528 2.528 0 0 1 0 15.165a2.527 2.527 0 0 1 2.522-2.52h2.52v2.52zm1.271 0a2.527 2.527 0 0 1 2.521-2.52 2.527 2.527 0 0 1 2.521 2.52v6.313A2.528 2.528 0 0 1 8.834 24a2.528 2.528 0 0 1-2.521-2.522v-6.313zM8.834 5.042a2.528 2.528 0 0 1-2.521-2.52A2.528 2.528 0 0 1 8.834 0a2.528 2.528 0 0 1 2.521 2.522v2.52H8.834zm0 1.271a2.528 2.528 0 0 1 2.521 2.521 2.528 2.528 0 0 1-2.521 2.521H2.522A2.528 2.528 0 0 1 0 8.834a2.528 2.528 0 0 1 2.522-2.521h6.312zM18.956 8.834a2.528 2.528 0 0 1 2.522-2.521A2.528 2.528 0 0 1 24 8.834a2.528 2.528 0 0 1-2.522 2.521h-2.522V8.834zm-1.27 0a2.528 2.528 0 0 1-2.523 2.521 2.527 2.527 0 0 1-2.52-2.521V2.522A2.527 2.527 0 0 1 15.163 0a2.528 2.528 0 0 1 2.523 2.522v6.312zM15.163 18.956a2.528 2.528 0 0 1 2.523 2.522A2.528 2.528 0 0 1 15.163 24a2.527 2.527 0 0 1-2.52-2.522v-2.522h2.52zm0-1.27a2.527 2.527 0 0 1-2.52-2.523 2.527 2.527 0 0 1 2.52-2.52h6.315A2.528 2.528 0 0 1 24 15.163a2.528 2.528 0 0 1-2.522 2.523h-6.315z" />
      </svg>
    </IconWrapper>
  )
}

function TeamsIcon() {
  return (
    <IconWrapper bg="bg-[#6264A7]/10">
      <svg className="h-5 w-5 text-[#6264A7]" viewBox="0 0 24 24" fill="currentColor">
        <path d="M20.625 8.25h-3.375v6.375a3.375 3.375 0 0 1-6.75 0V7.5H3.375A1.875 1.875 0 0 0 1.5 9.375v7.5a1.875 1.875 0 0 0 1.875 1.875h4.313L9 22.5l1.313-3.75h4.312a1.875 1.875 0 0 0 1.875-1.875V15h4.125A1.875 1.875 0 0 0 22.5 13.125v-3A1.875 1.875 0 0 0 20.625 8.25zM18 6a2.25 2.25 0 1 0 0-4.5A2.25 2.25 0 0 0 18 6zM9.75 6a3 3 0 1 0 0-6 3 3 0 0 0 0 6z" />
      </svg>
    </IconWrapper>
  )
}

function PagerDutyIcon() {
  return (
    <IconWrapper bg="bg-[#06AC38]/10">
      <svg className="h-5 w-5 text-[#06AC38]" viewBox="0 0 24 24" fill="currentColor">
        <path d="M12.006 0C5.391 0 1.127 3.6 1.127 9.166c0 5.185 3.736 8.669 9.674 8.669h1.205V24h3.263V0h-3.263zm-.076 14.783c-3.736 0-6.24-2.29-6.24-5.735 0-3.672 2.504-6.013 6.316-6.013h3.263v11.748h-3.339z" />
      </svg>
    </IconWrapper>
  )
}

function JiraIcon() {
  return (
    <IconWrapper bg="bg-[#0052CC]/10">
      <svg className="h-5 w-5 text-[#0052CC]" viewBox="0 0 24 24" fill="currentColor">
        <path d="M11.571 11.513H0a5.218 5.218 0 0 0 5.232 5.215h2.13v2.057A5.215 5.215 0 0 0 12.575 24V12.518a1.005 1.005 0 0 0-1.005-1.005zm5.723-5.756H5.736a5.215 5.215 0 0 0 5.215 5.214h2.129v2.058a5.218 5.218 0 0 0 5.215 5.214V6.758a1.001 1.001 0 0 0-1.001-1.001zM23 0H11.443a5.217 5.217 0 0 0 5.214 5.217h2.129v2.058A5.218 5.218 0 0 0 24 12.49V1.005A1.005 1.005 0 0 0 23 0z" />
      </svg>
    </IconWrapper>
  )
}

function LinearIcon() {
  return (
    <IconWrapper bg="bg-[#5E6AD2]/10">
      <svg className="h-5 w-5 text-[#5E6AD2]" viewBox="0 0 24 24" fill="currentColor">
        <path d="M2.652 15.555a.5.5 0 0 1-.048-.592C4.239 12.064 7.086 9.99 12 9.99s7.761 2.074 9.396 4.973a.5.5 0 0 1-.048.592L12 24 2.652 15.555zM12 0a9 9 0 1 0 0 18A9 9 0 0 0 12 0z" />
      </svg>
    </IconWrapper>
  )
}

function GitHubIcon() {
  return (
    <IconWrapper bg="bg-[var(--color-surface-raised)]">
      <svg className="h-5 w-5 text-[var(--color-text-primary)]" viewBox="0 0 24 24" fill="currentColor">
        <path d="M12 .297c-6.63 0-12 5.373-12 12 0 5.303 3.438 9.8 8.205 11.385.6.113.82-.258.82-.577 0-.285-.01-1.04-.015-2.04-3.338.724-4.042-1.61-4.042-1.61C4.422 18.07 3.633 17.7 3.633 17.7c-1.087-.744.084-.729.084-.729 1.205.084 1.838 1.236 1.838 1.236 1.07 1.835 2.809 1.305 3.495.998.108-.776.417-1.305.76-1.605-2.665-.3-5.466-1.332-5.466-5.93 0-1.31.465-2.38 1.235-3.22-.135-.303-.54-1.523.105-3.176 0 0 1.005-.322 3.3 1.23.96-.267 1.98-.399 3-.405 1.02.006 2.04.138 3 .405 2.28-1.552 3.285-1.23 3.285-1.23.645 1.653.24 2.873.12 3.176.765.84 1.23 1.91 1.23 3.22 0 4.61-2.805 5.625-5.475 5.92.42.36.81 1.096.81 2.22 0 1.606-.015 2.896-.015 3.286 0 .315.21.69.825.57C20.565 22.092 24 17.592 24 12.297c0-6.627-5.373-12-12-12" />
      </svg>
    </IconWrapper>
  )
}

function GitHubActionsIcon() {
  return (
    <IconWrapper bg="bg-[#2088FF]/10">
      <svg className="h-5 w-5 text-[#2088FF]" viewBox="0 0 24 24" fill="currentColor">
        <path d="M12 0C5.373 0 0 5.373 0 12s5.373 12 12 12 12-5.373 12-12S18.627 0 12 0zm-.857 17.47l-4.286-4.285 1.414-1.414 2.872 2.871 5.728-5.728 1.414 1.414-7.142 7.142z" />
      </svg>
    </IconWrapper>
  )
}

function GitLabIcon() {
  return (
    <IconWrapper bg="bg-[#FC6D26]/10">
      <svg className="h-5 w-5 text-[#FC6D26]" viewBox="0 0 24 24" fill="currentColor">
        <path d="m23.6 9.593-1.637-5.037a.376.376 0 0 0-.02-.058L20.3.907a.757.757 0 0 0-1.439.038l-1.563 4.795H6.702L5.14.945a.757.757 0 0 0-1.44-.038L2.057 4.498a.387.387 0 0 0-.02.058L.4 9.593a1.088 1.088 0 0 0 .393 1.216l11.073 8.044a.193.193 0 0 0 .228 0l11.073-8.044a1.088 1.088 0 0 0 .394-1.216" />
      </svg>
    </IconWrapper>
  )
}

function JenkinsIcon() {
  return (
    <IconWrapper bg="bg-[#D33833]/10">
      <svg className="h-5 w-5 text-[#D33833]" viewBox="0 0 24 24" fill="currentColor">
        <path d="M5.566 9.157a.455.455 0 1 1 .909 0 .455.455 0 0 1-.909 0zm7.783-1.59a5.869 5.869 0 0 1 4.485 2.063 5.878 5.878 0 0 1 1.321 4.903A5.881 5.881 0 0 1 6.078 16.6a5.881 5.881 0 0 1 7.271-9.034zM12 0C5.373 0 0 5.373 0 12s5.373 12 12 12 12-5.373 12-12S18.627 0 12 0z" />
      </svg>
    </IconWrapper>
  )
}

function WebhookIcon() {
  return (
    <IconWrapper bg="bg-[var(--color-surface-raised)]">
      <svg className="h-5 w-5 text-[var(--color-text-secondary)]" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.5} strokeLinecap="round" strokeLinejoin="round">
        <path d="M10.5 6h9.75M10.5 6a1.5 1.5 0 1 1-3 0m3 0a1.5 1.5 0 1 0-3 0M3.75 6H7.5m3 12h9.75m-9.75 0a1.5 1.5 0 0 1-3 0m3 0a1.5 1.5 0 0 0-3 0m-3.75 0H7.5m9-6h3.75m-3.75 0a1.5 1.5 0 0 1-3 0m3 0a1.5 1.5 0 0 0-3 0m-9.75 0h9.75" />
      </svg>
    </IconWrapper>
  )
}

function ApiKeyIcon() {
  return (
    <IconWrapper bg="bg-[var(--color-surface-raised)]">
      <svg className="h-5 w-5 text-[var(--color-text-secondary)]" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.5} strokeLinecap="round" strokeLinejoin="round">
        <path d="M15.75 5.25a3 3 0 0 1 3 3m3 0a6 6 0 0 1-7.029 5.912c-.563-.097-1.159.026-1.563.43L10.5 17.25H8.25v2.25H6v2.25H2.25v-2.818c0-.597.237-1.17.659-1.591l6.499-6.499c.404-.404.527-1 .43-1.563A6 6 0 1 1 21.75 8.25Z" />
      </svg>
    </IconWrapper>
  )
}

function EmailIcon() {
  return (
    <IconWrapper bg="bg-[var(--color-surface-raised)]">
      <svg className="h-5 w-5 text-[var(--color-text-secondary)]" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.5} strokeLinecap="round" strokeLinejoin="round">
        <path d="M21.75 6.75v10.5a2.25 2.25 0 0 1-2.25 2.25h-15a2.25 2.25 0 0 1-2.25-2.25V6.75m19.5 0A2.25 2.25 0 0 0 19.5 4.5h-15a2.25 2.25 0 0 0-2.25 2.25m19.5 0v.243a2.25 2.25 0 0 1-1.07 1.916l-7.5 4.615a2.25 2.25 0 0 1-2.36 0L3.32 8.91a2.25 2.25 0 0 1-1.07-1.916V6.75" />
      </svg>
    </IconWrapper>
  )
}
