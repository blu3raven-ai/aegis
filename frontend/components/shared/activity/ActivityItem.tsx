"use client"

import Link from "next/link"
import type { ActivityEvent } from "@/lib/client/activity-api"
import { relativeTime } from "@/lib/shared/relative-time"

// ── Event type metadata ───────────────────────────────────────────────────────

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
      return id != null ? `/findings/${id}` : "/findings"
    },
  },
  "finding.dismissed": {
    icon: "m9.75 9.75 4.5 4.5m0-4.5-4.5 4.5M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0Z",
    color: "var(--color-text-secondary)",
    href: (e) => {
      const id = e.payload?.finding_id
      return id != null ? `/findings/${id}` : "/findings"
    },
  },
  "finding.fixed": {
    icon: "M9 12.75 11.25 15 15 9.75M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0Z",
    color: "var(--color-severity-low)",
    href: (e) => {
      const id = e.payload?.finding_id
      return id != null ? `/findings/${id}` : "/findings"
    },
  },
  "finding.reopened": {
    icon: "M16.023 9.348h4.992v-.001M2.985 19.644v-4.992m0 0h4.992m-4.993 0 3.181 3.183a8.25 8.25 0 0 0 13.803-3.7M4.031 9.865a8.25 8.25 0 0 1 13.803-3.7l3.181 3.182m0-4.991v4.99",
    color: "var(--color-severity-high)",
    href: (e) => {
      const id = e.payload?.finding_id
      return id != null ? `/findings/${id}` : "/findings"
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
  "integration.connected": {
    icon: "M13.5 16.875h3.375m0 0h3.375m-3.375 0V13.5m0 3.375v3.375M6 10.5h2.25a2.25 2.25 0 0 0 2.25-2.25V6a2.25 2.25 0 0 0-2.25-2.25H6A2.25 2.25 0 0 0 3.75 6v2.25A2.25 2.25 0 0 0 6 10.5Zm0 9.75h2.25A2.25 2.25 0 0 0 10.5 18v-2.25a2.25 2.25 0 0 0-2.25-2.25H6a2.25 2.25 0 0 0-2.25 2.25V18A2.25 2.25 0 0 0 6 20.25Zm9.75-9.75H18a2.25 2.25 0 0 0 2.25-2.25V6A2.25 2.25 0 0 0 18 3.75h-2.25A2.25 2.25 0 0 0 13.5 6v2.25a2.25 2.25 0 0 0 2.25 2.25Z",
    color: "var(--color-accent)",
    href: () => "/settings/integrations",
  },
  "integration.disconnected": {
    icon: "M14.74 9l-.346 9m-4.788 0L9.26 9m9.968-3.21c.342.052.682.107 1.022.166m-1.022-.165L18.16 19.673a2.25 2.25 0 0 1-2.244 2.077H8.084a2.25 2.25 0 0 1-2.244-2.077L4.772 5.79m14.456 0a48.108 48.108 0 0 0-3.478-.397m-12 .562c.34-.059.68-.114 1.022-.165m0 0a48.11 48.11 0 0 1 3.478-.397m7.5 0v-.916c0-1.18-.91-2.164-2.09-2.201a51.964 51.964 0 0 0-3.32 0c-1.18.037-2.09 1.022-2.09 2.201v.916m7.5 0a48.667 48.667 0 0 0-7.5 0",
    color: "var(--color-text-secondary)",
    href: () => "/settings/integrations",
  },
  "intel.cve.added": {
    icon: "M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126ZM12 15.75h.007v.008H12v-.008Z",
    color: "var(--color-severity-high)",
    href: (e) => {
      const cve = e.payload?.cve_id as string | undefined
      return cve ? `/findings?cve=${encodeURIComponent(cve)}` : "/findings"
    },
  },
  "sla.breached": {
    icon: "M12 6v6h4.5m4.5 0a9 9 0 1 1-18 0 9 9 0 0 1 18 0Z",
    color: "var(--color-severity-critical)",
    href: (e) => {
      const id = e.payload?.finding_id
      return id != null ? `/findings/${id}` : "/findings"
    },
  },
  "kev.added": {
    icon: "M9 12.75 11.25 15 15 9.75m-3-7.036A11.959 11.959 0 0 1 3.598 6 11.99 11.99 0 0 0 3 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285Z",
    color: "var(--color-severity-critical)",
    href: (e) => {
      const cve = e.payload?.cve_id as string | undefined
      return cve ? `/findings?cve=${encodeURIComponent(cve)}` : "/findings"
    },
  },
}

const DEFAULT_META: EventMeta = {
  icon: "M12 6v6h4.5m4.5 0a9 9 0 1 1-18 0 9 9 0 0 1 18 0Z",
  color: "var(--color-text-secondary)",
  href: () => null,
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function formatTime(isoString: string): string {
  try {
    return new Date(isoString).toLocaleTimeString(undefined, {
      hour: "2-digit",
      minute: "2-digit",
      hour12: false,
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
  critical: "bg-[var(--color-severity-critical-subtle)] text-[var(--color-severity-critical)] border-[var(--color-severity-critical-border)]",
  high: "bg-[var(--color-severity-high-subtle)] text-[var(--color-severity-high)] border-[var(--color-severity-high-border)]",
  medium: "bg-[var(--color-severity-medium-subtle)] text-[var(--color-severity-medium)] border-[var(--color-severity-medium-border)]",
  low: "bg-[var(--color-severity-low-subtle)] text-[var(--color-severity-low)] border-[var(--color-severity-low-border)]",
}

const NEUTRAL_TONE = "bg-[var(--color-surface-raised)] text-[var(--color-text-secondary)] border-[var(--color-border)]"

// ── PayloadChip ───────────────────────────────────────────────────────────────

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

// ── Component ─────────────────────────────────────────────────────────────────

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
