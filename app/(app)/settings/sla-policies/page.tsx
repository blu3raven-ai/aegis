"use client"

import { useCallback, useEffect, useState } from "react"
import { listSlaPolicies, updateSlaPolicy, triggerRecompute } from "@/lib/client/sla-api"
import type { SlaPolicy, UpdateSlaPolicyPayload } from "@/lib/client/sla-api"
import { PolicyEditor } from "@/components/shared/sla/PolicyEditor"
import { SettingsCard } from "@/components/shared/SettingsCard"

const ORG_ID = process.env.NEXT_PUBLIC_ORG_ID ?? "example-org"

export default function SLAPoliciesPage() {
  const orgId = ORG_ID
  const [policies, setPolicies] = useState<SlaPolicy[]>([])
  const [loading, setLoading] = useState(true)
  const [loadError, setLoadError] = useState<string | null>(null)
  const [recomputing, setRecomputing] = useState(false)
  const [recomputeResult, setRecomputeResult] = useState<string | null>(null)
  const [lastRecomputed, setLastRecomputed] = useState<Date | null>(null)

  const load = useCallback(async () => {
    setLoading(true)
    setLoadError(null)
    try {
      const data = await listSlaPolicies(orgId)
      setPolicies(data)
    } catch (err) {
      setLoadError(err instanceof Error ? err.message : "Failed to load SLA policies")
    } finally {
      setLoading(false)
    }
  }, [orgId])

  useEffect(() => {
    void load()
  }, [load])

  async function handleSave(severity: string, payload: UpdateSlaPolicyPayload) {
    const updated = await updateSlaPolicy(orgId, severity, payload)
    setPolicies((prev) =>
      prev.map((p) => (p.severity === severity ? updated : p)),
    )
  }

  async function handleRecompute() {
    setRecomputing(true)
    setRecomputeResult(null)
    try {
      const result = await triggerRecompute(orgId)
      setRecomputeResult(`${result.updated} finding${result.updated !== 1 ? "s" : ""} updated`)
      setLastRecomputed(new Date())
    } catch (err) {
      setRecomputeResult(err instanceof Error ? err.message : "Recompute failed")
    } finally {
      setRecomputing(false)
    }
  }

  function formatLastRecomputed(d: Date | null): string {
    if (!d) return "Never"
    const diffMs = Date.now() - d.getTime()
    const diffMin = Math.floor(diffMs / 60_000)
    if (diffMin < 1) return "Just now"
    if (diffMin === 1) return "1 minute ago"
    return `${diffMin} minutes ago`
  }

  return (
    <div className="mx-auto max-w-5xl p-6 lg:p-10 space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-lg font-semibold tracking-tight text-[var(--color-text-primary)]">SLA Policies</h1>
        <p className="mt-1 text-sm text-[var(--color-text-secondary)]">
          Set deadlines per severity for findings remediation. Breach status is recomputed hourly.
        </p>
      </div>

      {/* Policy table */}
      <SettingsCard
        eyebrow="Remediation deadlines"
        title="Per-severity SLA policies"
        subtitle="Findings that exceed their deadline are flagged as SLA-breached in the dashboard."
      >
        {loading ? (
          <div className="space-y-3">
            {[...Array(4)].map((_, i) => (
              <div key={i} className="h-9 rounded-lg bg-[var(--color-surface-raised)] motion-safe:animate-pulse" />
            ))}
          </div>
        ) : loadError ? (
          <div className="flex items-center justify-between rounded-lg border border-[var(--color-severity-high)]/20 bg-[var(--color-severity-high)]/5 px-4 py-3">
            <span className="text-sm text-[var(--color-severity-high)]">{loadError}</span>
            <button
              type="button"
              onClick={load}
              className="text-xs font-semibold text-[var(--color-accent)] hover:underline focus-visible:outline-none"
            >
              Retry
            </button>
          </div>
        ) : (
          <PolicyEditor policies={policies} onSave={handleSave} />
        )}
      </SettingsCard>

      {/* Recompute card */}
      <SettingsCard
        eyebrow="Maintenance"
        title="Recompute SLA status"
        subtitle="SLA breach status updates hourly. Trigger an immediate recompute if you've just changed policies."
      >
        <div className="flex items-center justify-between gap-4">
          <div className="text-xs text-[var(--color-text-tertiary)]">
            Last recomputed: {formatLastRecomputed(lastRecomputed)}
            {recomputeResult && (
              <span className="ml-2 text-[var(--color-text-secondary)]">— {recomputeResult}</span>
            )}
          </div>
          <button
            type="button"
            onClick={handleRecompute}
            disabled={recomputing}
            className="rounded-lg border border-[var(--color-border)] bg-[var(--color-surface)] px-3 py-1.5 text-xs font-semibold text-[var(--color-text-primary)] transition-colors hover:bg-[var(--color-surface-raised)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)] disabled:opacity-50"
          >
            {recomputing ? "Recomputing…" : "Recompute now"}
          </button>
        </div>
      </SettingsCard>
    </div>
  )
}
