"use client"

import type { ReactNode } from "react"

export type ReportTemplateId =
  | "findings-export"
  | "posture-snapshot"
  | "monthly-executive"
  | "quarterly-risk"
  | "soc2-evidence"
  | "pci-attestation"

type TemplateTag = "scheduled" | "audit" | "adhoc"

interface ReportTemplate {
  id: ReportTemplateId
  title: string
  description: string
  tag: TemplateTag
  formats: string[]
  enabled: boolean
  icon: ReactNode
  iconClass: string
}

interface ReportTemplateGridProps {
  onSelect: (id: ReportTemplateId) => void
  /**
   * Per-template reasons to disable a card at runtime — e.g. a compliance
   * attestation whose framework the workspace doesn't track. The reason is
   * shown on the card and as its tooltip so the user knows how to enable it.
   */
  disabledReasons?: Partial<Record<ReportTemplateId, string>>
}

const TAG_LABEL: Record<TemplateTag, string> = {
  scheduled: "Scheduled",
  audit: "Audit",
  adhoc: "Ad-hoc",
}

const TAG_CLASS: Record<TemplateTag, string> = {
  scheduled:
    "bg-[var(--color-severity-low-subtle)] text-[var(--color-severity-low-text)]",
  audit:
    "bg-[var(--color-accent-subtle)] text-[var(--color-accent)]",
  adhoc:
    "bg-[var(--color-surface-raised)] text-[var(--color-text-secondary)]",
}

const TEMPLATES: ReportTemplate[] = [
  {
    id: "findings-export",
    title: "Findings export",
    description:
      "Full findings dataset with severity, owner, repo, and status. Pull for spreadsheet review or ticket import.",
    tag: "adhoc",
    formats: ["CSV", "JSON"],
    enabled: true,
    iconClass:
      "bg-[var(--color-accent-subtle)] text-[var(--color-accent)]",
    icon: (
      <svg
        viewBox="0 0 24 24"
        fill="none"
        stroke="currentColor"
        strokeWidth={1.5}
        strokeLinecap="round"
        strokeLinejoin="round"
        className="h-[18px] w-[18px]"
        aria-hidden="true"
      >
        <path d="M9 12.75 11.25 15 15 9.75" />
        <path d="M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0Z" />
      </svg>
    ),
  },
  {
    id: "posture-snapshot",
    title: "Posture snapshot",
    description:
      "Current security posture across repositories, images, and integrations. Captures state at run time.",
    tag: "adhoc",
    formats: ["JSON"],
    enabled: true,
    iconClass:
      "bg-[var(--color-accent-subtle)] text-[var(--color-accent)]",
    icon: (
      <svg
        viewBox="0 0 24 24"
        fill="none"
        stroke="currentColor"
        strokeWidth={1.5}
        strokeLinecap="round"
        strokeLinejoin="round"
        className="h-[18px] w-[18px]"
        aria-hidden="true"
      >
        <path d="M2.25 18 9 11.25l4.306 4.306a11.95 11.95 0 0 1 5.814-5.518l2.74-1.22" />
        <path d="m21.31 8.818-5.94-2.281m5.94 2.28-2.28 5.941" />
      </svg>
    ),
  },
  {
    id: "monthly-executive",
    title: "Monthly executive review",
    description:
      "KPI summary, 30-day open-findings trend, mean-time-to-fix, top repositories, and the most urgent findings. Built for CISO board updates.",
    tag: "scheduled",
    formats: ["PDF"],
    enabled: true,
    iconClass:
      "bg-[var(--color-severity-low-subtle)] text-[var(--color-severity-low-text)]",
    icon: (
      <svg
        viewBox="0 0 24 24"
        fill="none"
        stroke="currentColor"
        strokeWidth={1.5}
        strokeLinecap="round"
        strokeLinejoin="round"
        className="h-[18px] w-[18px]"
        aria-hidden="true"
      >
        <path d="M2.25 18 9 11.25l4.306 4.306a11.95 11.95 0 0 1 5.814-5.518l2.74-1.22" />
        <path d="m21.31 8.818-5.94-2.281m5.94 2.28-2.28 5.941" />
      </svg>
    ),
  },
  {
    id: "quarterly-risk",
    title: "Quarterly risk register",
    description:
      "Open findings by severity, age, owner, and repo. Accepted-risk log with rationale for compliance.",
    tag: "audit",
    formats: ["CSV", "PDF"],
    enabled: true,
    iconClass:
      "bg-[var(--color-severity-high-subtle)] text-[var(--color-severity-high-text)]",
    icon: (
      <svg
        viewBox="0 0 24 24"
        fill="none"
        stroke="currentColor"
        strokeWidth={1.5}
        strokeLinecap="round"
        strokeLinejoin="round"
        className="h-[18px] w-[18px]"
        aria-hidden="true"
      >
        <path d="M12 9v3.75" />
        <path d="M2.697 16.126c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126Z" />
        <path d="M12 15.75h.007v.008H12v-.008Z" />
      </svg>
    ),
  },
  {
    id: "soc2-evidence",
    title: "SOC 2 Type II evidence",
    description:
      "Control mapping with evidence per control (CC6.1-CC9.2), 90-day finding lifecycle, and dismissal audit trail.",
    tag: "audit",
    formats: ["ZIP"],
    enabled: true,
    iconClass:
      "bg-[var(--color-severity-low-subtle)] text-[var(--color-severity-low-text)]",
    icon: (
      <svg
        viewBox="0 0 24 24"
        fill="none"
        stroke="currentColor"
        strokeWidth={1.5}
        strokeLinecap="round"
        strokeLinejoin="round"
        className="h-[18px] w-[18px]"
        aria-hidden="true"
      >
        <path d="M9 12.75 11.25 15 15 9.75" />
        <path d="M21 12c0 1.268-.63 2.39-1.593 3.068a3.745 3.745 0 0 1-1.043 3.296 3.745 3.745 0 0 1-3.296 1.043A3.745 3.745 0 0 1 12 21c-1.268 0-2.39-.63-3.068-1.593a3.746 3.746 0 0 1-3.296-1.043 3.745 3.745 0 0 1-1.043-3.296A3.745 3.745 0 0 1 3 12c0-1.268.63-2.39 1.593-3.068a3.745 3.745 0 0 1 1.043-3.296 3.746 3.746 0 0 1 3.296-1.043A3.746 3.746 0 0 1 12 3c1.268 0 2.39.63 3.068 1.593a3.746 3.746 0 0 1 3.296 1.043 3.746 3.746 0 0 1 1.043 3.296A3.745 3.745 0 0 1 21 12Z" />
      </svg>
    ),
  },
  {
    id: "pci-attestation",
    title: "PCI DSS attestation",
    description:
      "CDE-scoped findings with requirement-by-requirement compliance status for QSA review.",
    tag: "audit",
    formats: ["PDF"],
    enabled: true,
    iconClass:
      "bg-[var(--color-accent-subtle)] text-[var(--color-accent)]",
    icon: (
      <svg
        viewBox="0 0 24 24"
        fill="none"
        stroke="currentColor"
        strokeWidth={1.5}
        strokeLinecap="round"
        strokeLinejoin="round"
        className="h-[18px] w-[18px]"
        aria-hidden="true"
      >
        <path d="M2.25 8.25h19.5" />
        <path d="M2.25 9h19.5" />
        <path d="M5.25 14.25h6" />
        <path d="M5.25 16.5h3" />
        <path d="M4.5 19.5h15a2.25 2.25 0 0 0 2.25-2.25V6.75A2.25 2.25 0 0 0 19.5 4.5h-15a2.25 2.25 0 0 0-2.25 2.25v10.5A2.25 2.25 0 0 0 4.5 19.5Z" />
      </svg>
    ),
  },
]

export function ReportTemplateGrid({ onSelect, disabledReasons }: ReportTemplateGridProps) {
  return (
    <section aria-label="Report templates">
      <h2 className="font-mono text-2xs font-semibold uppercase tracking-[0.14em] text-[var(--color-text-tertiary)] mb-3">
        Templates
      </h2>
      <div className="grid grid-cols-1 gap-3.5 md:grid-cols-2 lg:grid-cols-3">
        {TEMPLATES.map(template => (
          <TemplateTile
            key={template.id}
            template={template}
            onSelect={onSelect}
            disabledReason={disabledReasons?.[template.id]}
          />
        ))}
      </div>
    </section>
  )
}

function TemplateTile({
  template,
  onSelect,
  disabledReason,
}: {
  template: ReportTemplate
  onSelect: (id: ReportTemplateId) => void
  disabledReason?: string
}) {
  const { title, description, tag, formats, enabled, icon, iconClass } = template

  // Static `enabled: false` means "coming soon"; a runtime `disabledReason`
  // means the capability exists but isn't available for this workspace yet.
  const interactive = enabled && !disabledReason

  const baseClass =
    "group relative flex h-full flex-col rounded-md border border-[var(--color-border)] bg-[var(--color-surface)] p-5 text-left transition-all"
  const stateClass = interactive
    ? "cursor-pointer hover:border-[var(--color-border-strong)] hover:bg-[var(--color-surface-raised)] hover:shadow-md focus:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)] focus-visible:ring-offset-2 focus-visible:ring-offset-[var(--color-background)]"
    : "cursor-not-allowed opacity-60"

  return (
    <button
      type="button"
      onClick={() => interactive && onSelect(template.id)}
      disabled={!interactive}
      aria-disabled={!interactive}
      title={disabledReason}
      aria-label={
        interactive
          ? `Use ${title} template`
          : disabledReason
            ? `${title}: ${disabledReason}`
            : `${title}: coming soon`
      }
      className={`${baseClass} ${stateClass}`}
    >
      {/* Head row — mock report-card-head: icon left, tag right */}
      <div className="mb-3 flex items-start justify-between gap-3">
        <div
          className={`flex h-9 w-9 items-center justify-center rounded-lg ${iconClass}`}
        >
          {icon}
        </div>
        {interactive ? (
          <span
            className={`font-mono text-2xs font-semibold uppercase tracking-[0.14em] rounded px-1.5 py-0.5 ${TAG_CLASS[tag]}`}
          >
            {TAG_LABEL[tag]}
          </span>
        ) : (
          <span className="rounded border border-[var(--color-border)] bg-[var(--color-surface-raised)] px-1.5 py-0.5 font-mono text-2xs font-semibold uppercase tracking-[0.14em] text-[var(--color-text-tertiary)]">
            {disabledReason ? "Unavailable" : "Coming soon"}
          </span>
        )}
      </div>
      <h3 className="text-base font-semibold text-[var(--color-text-primary)] mb-1">
        {title}
      </h3>
      <p className="text-sm text-[var(--color-text-secondary)] leading-relaxed mb-4 flex-1">
        {description}
      </p>
      {/* Foot row — mock report-foot: format pills left, action label right */}
      <div className="flex items-center justify-between gap-3 pt-3 border-t border-[var(--color-border)]">
        <div className="flex flex-wrap items-center gap-1.5">
          {formats.map(fmt => (
            <span
              key={fmt}
              className="font-mono text-2xs font-semibold uppercase tracking-[0.06em] rounded px-1.5 py-0.5 bg-[var(--color-surface-raised)] text-[var(--color-text-tertiary)]"
            >
              {fmt}
            </span>
          ))}
        </div>
        {interactive ? (
          <span className="shrink-0 text-xs font-semibold text-[var(--color-accent)] transition-transform group-hover:translate-x-0.5">
            Use template →
          </span>
        ) : disabledReason ? (
          <span className="shrink-0 text-xs font-medium text-[var(--color-text-tertiary)]">
            {disabledReason}
          </span>
        ) : null}
      </div>
    </button>
  )
}
