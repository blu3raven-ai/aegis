"use client"

import Link from "next/link"
import type { ActivityEvent } from "@/lib/client/activity-api"
import { relativeTime } from "@/lib/shared/relative-time"
import { getActiveTimeZone } from "@/lib/client/active-timezone"


interface EventMeta {
  icon: string
  color: string
  href: (e: ActivityEvent) => string | null
}

const EVENT_META: Record<string, EventMeta> = {
  "finding.created": {
    icon: "M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126ZM12 15.75h.007v.008H12v-.008Z",
    color: "var(--color-severity-medium)",
    href: (e) => {
      const id = e.payload?.finding_id
      return id != null ? `/findings?finding=${id}` : "/findings"
    },
  },
  "finding.dismissed": {
    icon: "m9.75 9.75 4.5 4.5m0-4.5-4.5 4.5M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0Z",
    color: "var(--color-text-secondary)",
    href: (e) => {
      const id = e.payload?.finding_id
      return id != null ? `/findings?finding=${id}` : "/findings"
    },
  },
  "finding.fixed": {
    icon: "M9 12.75 11.25 15 15 9.75M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0Z",
    color: "var(--color-severity-low)",
    href: (e) => {
      const id = e.payload?.finding_id
      return id != null ? `/findings?finding=${id}` : "/findings"
    },
  },
  "finding.reopened": {
    icon: "M16.023 9.348h4.992v-.001M2.985 19.644v-4.992m0 0h4.992m-4.993 0 3.181 3.183a8.25 8.25 0 0 0 13.803-3.7M4.031 9.865a8.25 8.25 0 0 1 13.803-3.7l3.181 3.182m0-4.991v4.99",
    color: "var(--color-severity-high)",
    href: (e) => {
      const id = e.payload?.finding_id
      return id != null ? `/findings?finding=${id}` : "/findings"
    },
  },
  "scan.completed": {
    icon: "M9 12.75 11.25 15 15 9.75m-3-7.036A11.959 11.959 0 0 1 3.598 6 11.99 11.99 0 0 0 3 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285Z",
    color: "var(--color-accent)",
    href: (e) => {
      const repo = e.repo_id
      return repo ? `/repos` : null
    },
  },
  "scan.failed": {
    icon: "M12 9v3.75m9-.75a9 9 0 1 1-18 0 9 9 0 0 1 18 0Zm-9 3.75h.008v.008H12v-.008Z",
    color: "var(--color-severity-critical)",
    href: (e) => {
      const repo = e.repo_id
      return repo ? `/repos` : null
    },
  },
  "scan.cancelled": {
    icon: "M18.364 18.364A9 9 0 0 0 5.636 5.636m12.728 12.728A9 9 0 0 1 5.636 5.636m12.728 12.728L5.636 5.636",
    color: "var(--color-text-secondary)",
    href: (e) => {
      const repo = e.repo_id
      return repo ? `/repos` : null
    },
  },
}

const DEFAULT_META: EventMeta = {
  icon: "M12 6v6h4.5m4.5 0a9 9 0 1 1-18 0 9 9 0 0 1 18 0Z",
  color: "var(--color-text-secondary)",
  href: () => null,
}


function formatTime(isoString: string): string {
  try {
    return new Date(isoString).toLocaleTimeString(undefined, {
      hour: "2-digit",
      minute: "2-digit",
      hour12: false,
      timeZone: getActiveTimeZone(),
    })
  } catch {
    return ""
  }
}

const SEVERITY_TONES = new Set(["critical", "high", "medium", "low"] as const)
type SeverityTone = "critical" | "high" | "medium" | "low"

function severityTone(s: string): SeverityTone | undefined {
  return SEVERITY_TONES.has(s as SeverityTone) ? (s as SeverityTone) : undefined
}

// Tailwind v4 only emits literal class names; dynamic interpolation would silently no-op.
const TONE_CLASSES: Record<SeverityTone, string> = {
  critical: "bg-[var(--color-severity-critical-subtle)] text-[var(--color-severity-critical-text)] border-[var(--color-severity-critical-border)]",
  high: "bg-[var(--color-severity-high-subtle)] text-[var(--color-severity-high-text)] border-[var(--color-severity-high-border)]",
  medium: "bg-[var(--color-severity-medium-subtle)] text-[var(--color-severity-medium-text)] border-[var(--color-severity-medium-border)]",
  low: "bg-[var(--color-severity-low-subtle)] text-[var(--color-severity-low-text)] border-[var(--color-severity-low-border)]",
}

const NEUTRAL_TONE = "bg-[var(--color-surface-raised)] text-[var(--color-text-secondary)] border-[var(--color-border)]"


interface PayloadChipProps {
  label: string
  tone?: SeverityTone
  mono?: boolean
}

function PayloadChip({ label, tone, mono }: PayloadChipProps) {
  const base = "inline-flex items-center rounded px-1.5 py-0.5 text-2xs border"
  const colorClasses = tone ? TONE_CLASSES[tone] : NEUTRAL_TONE
  const fontClass = mono ? "font-mono" : ""

  return (
    <span className={`${base} ${colorClasses} ${fontClass}`.trim()}>
      {label}
    </span>
  )
}


interface ActivityItemProps {
  event: ActivityEvent
}

export function ActivityItem({ event }: ActivityItemProps) {
  const meta = EVENT_META[event.type] ?? DEFAULT_META
  const href = meta.href(event)

  // Safely narrow payload fields before rendering chips
  const repoId = typeof event.payload?.repo_id === "string" && event.payload.repo_id ? event.payload.repo_id : null
  const rawSeverity = typeof event.payload?.severity === "string" && event.payload.severity ? event.payload.severity : null
  const tool = typeof event.payload?.tool === "string" && event.payload.tool ? event.payload.tool : null
  const cveId = typeof event.payload?.cve_id === "string" && event.payload.cve_id ? event.payload.cve_id : null
  const kev = event.payload?.kev === true

  const content = (
    <div
      className="group flex items-start gap-3 rounded-lg px-3 py-3 transition-colors hover:bg-[var(--color-surface-raised)]"
      data-testid="activity-item"
      data-event-type={event.type}
    >
      {/* Icon dot */}
      <div className="mt-0.5 flex h-7 w-7 shrink-0 items-center justify-center rounded-full bg-[var(--color-surface-raised)] ring-1 ring-[var(--color-border)]">
        <svg
          className="h-3.5 w-3.5"
          viewBox="0 0 24 24"
          fill="none"
          stroke={meta.color}
          strokeWidth={1.8}
          strokeLinecap="round"
          strokeLinejoin="round"
          aria-hidden="true"
        >
          <path d={meta.icon} />
        </svg>
      </div>

      {/* Body */}
      <div className="min-w-0 flex-1">
        <p className="text-sm font-medium text-[var(--color-text-primary)] leading-snug">
          {event.summary}
        </p>
        {(repoId || rawSeverity || tool || cveId || kev) && (
          <div className="mt-1 flex flex-wrap gap-1.5">
            {repoId && <PayloadChip label={repoId} />}
            {rawSeverity && <PayloadChip label={rawSeverity} tone={severityTone(rawSeverity)} />}
            {tool && <PayloadChip label={tool} />}
            {cveId && <PayloadChip label={cveId} mono />}
            {kev && <PayloadChip label="KEV" tone="critical" />}
          </div>
        )}
      </div>

      {/* Dual time column */}
      <div className="text-right text-2xs text-[var(--color-text-tertiary)] tabular-nums shrink-0">
        <div>{relativeTime(event.occurred_at)}</div>
        <div>{formatTime(event.occurred_at)}</div>
      </div>

      {/* Chevron hint */}
      {href && (
        <svg
          className="mt-1.5 h-3.5 w-3.5 shrink-0 text-[var(--color-text-secondary)] opacity-0 transition-opacity group-hover:opacity-100"
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          strokeWidth={2}
          strokeLinecap="round"
          strokeLinejoin="round"
          aria-hidden="true"
        >
          <path d="m9 18 6-6-6-6" />
        </svg>
      )}
    </div>
  )

  if (!href) return content

  return (
    <Link href={href} className="block" prefetch={false}>
      {content}
    </Link>
  )
}
