"use client"

import { useState, type ReactNode } from "react"

import type { FindingAdvisory } from "@/lib/client/findings-api"
import {
  cvssBaseScore,
  parseCvssVector,
  type CvssSeverity,
  type CvssTone,
} from "@/lib/shared/findings/cvss"

const CVSS_SCORE_TONE: Record<CvssSeverity, string> = {
  Critical: "text-[var(--color-severity-critical)]",
  High: "text-[var(--color-severity-high)]",
  Medium: "text-[var(--color-severity-medium)]",
  Low: "text-[var(--color-severity-low)]",
  None: "text-[var(--color-text-secondary)]",
}

function formatDate(iso: string | null): string | null {
  if (!iso) return null
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return null
  return d.toISOString().slice(0, 10)
}

const CVSS_TONE: Record<CvssTone, string> = {
  danger: "text-[var(--color-severity-critical)]",
  warn: "text-[var(--color-severity-high)]",
  neutral: "text-[var(--color-text-secondary)]",
}

/** CVSS field: the computed base score + severity (when derivable) leading the
 *  raw vector, with the decoded breakdown beneath. */
function CvssField({ vector }: { vector: string }) {
  const scored = cvssBaseScore(vector)
  return (
    <div>
      <Field label="CVSS">
        <span className="flex flex-wrap items-baseline gap-2">
          {scored && (
            <span
              className={`text-base font-semibold tabular-nums ${CVSS_SCORE_TONE[scored.severity]}`}
            >
              {scored.score.toFixed(1)} {scored.severity}
            </span>
          )}
          <span className="break-all font-mono text-xs text-[var(--color-text-secondary)]">
            {vector}
          </span>
        </span>
      </Field>
      <CvssBreakdown vector={vector} />
    </div>
  )
}

/** Decoded CVSS base metrics as compact label/value rows; renders nothing for
 *  a missing or non-v3 vector. */
function CvssBreakdown({ vector }: { vector: string }) {
  const metrics = parseCvssVector(vector)
  if (metrics.length === 0) return null
  return (
    <div className="mt-2 grid grid-cols-2 gap-x-6 gap-y-1">
      {metrics.map((m) => (
        <div key={m.label} className="flex items-baseline justify-between gap-2 text-xs">
          <span className="text-[var(--color-text-secondary)]">{m.label}</span>
          <span className={`font-medium ${CVSS_TONE[m.tone]}`}>{m.value}</span>
        </div>
      ))}
    </div>
  )
}

function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div>
      <dt className="text-2xs font-semibold uppercase tracking-[0.14em] text-[var(--color-text-secondary)]">
        {label}
      </dt>
      <dd className="mt-0.5 text-sm text-[var(--color-text-primary)]">{children}</dd>
    </div>
  )
}

/**
 * Advisory "Security Brief" for a dependency/container finding: the advisory
 * summary plus the facts an analyst weighs before acting — CVSS vector, the
 * affected → patched version range, and the publish date. Sourced from the OSV
 * advisory mirror via the finding's detail blob. Renders nothing for findings
 * without an advisory (the prop is null), so callers don't need to guard.
 */
export function SecurityBriefSection({
  advisory,
}: {
  advisory: FindingAdvisory | null | undefined
}) {
  const [expanded, setExpanded] = useState(false)
  if (!advisory) return null

  const published = formatDate(advisory.published_at)
  // The full advisory body is worth showing, but only when it adds detail
  // beyond the one-line summary already rendered above.
  const description =
    advisory.description && advisory.description.trim() !== (advisory.summary ?? "").trim()
      ? advisory.description
      : null
  const hasFacts = Boolean(
    advisory.cvss_vector || advisory.affected_range || advisory.fixed_version || published,
  )
  const kev = advisory.kev_detail ?? null
  if (!advisory.summary && !description && !hasFacts && !kev) return null

  const kevDue = formatDate(kev?.due_date ?? null)

  return (
    <section className="mt-6">
      <h3 className="mb-2 text-2xs font-semibold uppercase tracking-[0.14em] text-[var(--color-text-secondary)]">
        Security brief
      </h3>

      {kev && (
        <div className="mb-3 rounded border border-[color-mix(in_srgb,var(--color-severity-critical)_45%,transparent)] bg-[color-mix(in_srgb,var(--color-severity-critical)_10%,transparent)] p-3">
          <div className="flex flex-wrap items-center gap-2">
            <svg viewBox="0 0 24 24" className="h-4 w-4 shrink-0 text-[var(--color-severity-critical)]" fill="currentColor" aria-hidden="true">
              <path d="M13 2 3 14h7l-1 8 10-12h-7l1-8z" />
            </svg>
            <span className="text-sm font-semibold text-[var(--color-severity-critical)]">
              CISA Known Exploited
            </span>
            {kev.known_ransomware && (
              <span className="rounded-md border border-[color-mix(in_srgb,var(--color-severity-critical)_45%,transparent)] px-1.5 py-0.5 text-2xs font-semibold uppercase tracking-[0.1em] text-[var(--color-severity-critical)]">
                Ransomware
              </span>
            )}
          </div>
          <p className="mt-1 text-xs text-[var(--color-text-secondary)]">
            {kevDue
              ? `Federal agencies must remediate by ${kevDue}.`
              : "Actively exploited in the wild — prioritise remediation."}
          </p>
        </div>
      )}

      {advisory.summary && (
        <p className="text-sm leading-relaxed text-[var(--color-text-primary)]">
          {advisory.summary}
        </p>
      )}

      {description && (
        <div className="mt-2">
          {expanded && (
            <p className="whitespace-pre-wrap text-sm leading-relaxed text-[var(--color-text-secondary)]">
              {description}
            </p>
          )}
          <button
            type="button"
            onClick={() => setExpanded((v) => !v)}
            aria-expanded={expanded}
            className="mt-1 text-xs font-medium text-[var(--color-accent)] hover:underline"
          >
            {expanded ? "Show less" : "Read full advisory"}
          </button>
        </div>
      )}

      {hasFacts && (
        <div className="mt-3 space-y-3">
          {advisory.cvss_vector && <CvssField vector={advisory.cvss_vector} />}
          {(advisory.affected_range || advisory.fixed_version || published) && (
            <dl className="grid grid-cols-2 gap-x-6 gap-y-3">
              {advisory.affected_range && (
                <Field label="Affected">
                  <span className="font-mono text-xs">{advisory.affected_range}</span>
                </Field>
              )}
              {advisory.fixed_version && (
                <Field label="Fixed in">
                  <span className="font-mono text-xs text-[var(--color-status-ok)]">
                    {advisory.fixed_version}
                  </span>
                </Field>
              )}
              {published && <Field label="Published">{published}</Field>}
            </dl>
          )}
        </div>
      )}
    </section>
  )
}
