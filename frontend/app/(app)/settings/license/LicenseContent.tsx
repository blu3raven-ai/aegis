"use client"

import { useState } from "react"
import Link from "next/link"
import { useLicense, fetchLicenseStatus, invalidateLicenseCache } from "@/lib/client/license/client"
import { TIER_LABELS, type LicenseStatus, type Tier } from "@/lib/shared/license/types"
import { Dialog } from "@/components/layout/Dialog"
import { sectionHeadingClass } from "@/lib/shared/settings-styles"
import { apiClient } from "@/lib/client/api-client.ts"
import { ApiClientError } from "@/lib/client/api-client.types.ts"

function formatExpiryDate(value: string | number): string {
  const ts = typeof value === "string" && /^\d+$/.test(value) ? Number(value) : value
  const date = new Date(typeof ts === "number" && ts < 1e12 ? ts * 1000 : ts)
  if (isNaN(date.getTime())) return "Unknown"
  return date.toLocaleDateString(undefined, { year: "numeric", month: "long", day: "numeric" })
}

const TIER_COLORS: Record<Tier, string> = {
  community: "bg-[var(--color-surface-raised)] text-[var(--color-text-secondary)]",
  enterprise: "bg-[var(--color-accent)]/10 text-[var(--color-accent)]",
}

const FOCUS_RING = "focus-visible:ring-2 focus-visible:ring-[var(--color-accent)] focus-visible:outline-none"

export function LicenseContent() {
  const { tier, addons, limits, usage, license, isLoading } = useLicense()
  const hasArgus = addons?.includes("argus") ?? false

  const [key, setKey] = useState("")
  const [activating, setActivating] = useState(false)
  const [activateMsg, setActivateMsg] = useState<{ ok: boolean; text: string } | null>(null)

  const [showRemoveConfirm, setShowRemoveConfirm] = useState(false)
  const [removing, setRemoving] = useState(false)

  const [localStatus, setLocalStatus] = useState<LicenseStatus | null>(null)
  const displayTier = localStatus?.tier ?? tier
  const displayLicense = localStatus !== null ? localStatus.license : license
  const displayLimits = localStatus?.limits ?? limits
  const displayUsage = localStatus?.usage ?? usage

  async function handleActivate() {
    if (!key.trim()) return
    setActivating(true)
    setActivateMsg(null)
    try {
      await apiClient("/license/api/activate", {
        method: "POST",
        body: { key: key.trim() },
      })
      setActivateMsg({ ok: true, text: "License activated successfully." })
      setKey("")
      invalidateLicenseCache()
      const updated = await fetchLicenseStatus()
      setLocalStatus(updated)
    } catch (err) {
      if (err instanceof ApiClientError) {
        const body = err.body as { error?: string } | null
        setActivateMsg({ ok: false, text: body?.error ?? "Invalid license key. Check the key and try again." })
      } else {
        setActivateMsg({ ok: false, text: "Network error. Check your connection and try again." })
      }
    } finally {
      setActivating(false)
    }
  }

  async function handleRemove() {
    setShowRemoveConfirm(false)
    setRemoving(true)
    try {
      await apiClient("/license/api/remove", { method: "DELETE" })
      invalidateLicenseCache()
      const updated = await fetchLicenseStatus()
      setLocalStatus(updated)
      setActivateMsg({ ok: true, text: "License removed." })
    } catch {
      setActivateMsg({ ok: false, text: "Network error. Please try again." })
    } finally {
      setRemoving(false)
    }
  }

  if (isLoading) {
    return (
      <div className="space-y-4">
        <div className="h-20 motion-safe:animate-pulse rounded-2xl bg-[var(--color-surface-raised)]" />
        <div className="h-16 motion-safe:animate-pulse rounded-2xl bg-[var(--color-surface-raised)]" />
        <div className="h-40 motion-safe:animate-pulse rounded-2xl bg-[var(--color-surface-raised)]" />
      </div>
    )
  }

  return (
    <div className="space-y-4">
      <Dialog
        open={showRemoveConfirm}
        onClose={() => setShowRemoveConfirm(false)}
        onConfirm={handleRemove}
        title="Remove License"
        description="You'll return to the Community plan. Enterprise features will no longer be available."
        confirmLabel="Remove License"
        variant="danger"
      />

      <div className="space-y-8">
        {/* Current plan */}
        <div>
          <p className={sectionHeadingClass}>Current Plan</p>
          <div className="rounded-2xl border border-[var(--color-border)] bg-[var(--color-surface)] px-6 py-5">
            <div className="flex items-center gap-3">
              <span className={`rounded-full px-2.5 py-0.5 text-xs font-semibold ${TIER_COLORS[displayTier]}`}>
                {TIER_LABELS[displayTier]}
              </span>
              {hasArgus && (
                <span className="rounded-full bg-[var(--color-argus-subtle)] px-2.5 py-0.5 text-xs font-semibold text-[var(--color-argus)]">
                  Argus
                </span>
              )}
            </div>
            {displayLicense ? (
              <div className="mt-3 space-y-1 text-sm text-[var(--color-text-secondary)]">
                <p>Organization: <span className="text-[var(--color-text-primary)]">{displayLicense.org}</span></p>
                <p>Expires: <span className="text-[var(--color-text-primary)]">{formatExpiryDate(displayLicense.expiresAt)}</span></p>
              </div>
            ) : (
              <p className="mt-3 text-sm text-[var(--color-text-secondary)]">
                You're on the free Community plan. All scanning tools and dashboard features are included.
              </p>
            )}
          </div>
        </div>

        {/* Activate license */}
        <div>
          <p className={sectionHeadingClass}>Activate License</p>
          <div className="rounded-2xl border border-[var(--color-border)] bg-[var(--color-surface)] px-6 py-5">
            <div className="flex gap-3">
              <div className="flex-1">
                <label htmlFor="license-key" className="sr-only">License key</label>
                <input
                  id="license-key"
                  type="text"
                  value={key}
                  onChange={(e) => setKey(e.target.value)}
                  placeholder="Paste your license key"
                  className={`h-11 w-full rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-input)] px-3 text-sm text-[var(--color-text-primary)] placeholder:text-[var(--color-text-tertiary)] ${FOCUS_RING}`}
                  onKeyDown={(e) => {
                    if (e.key === "Enter") void handleActivate()
                  }}
                />
                <p className="mt-1.5 text-[11px] text-[var(--color-text-tertiary)]">
                  Paste the key from your license email. Works for Enterprise and Argus add-on licenses.
                </p>
              </div>
              <button
                type="button"
                onClick={() => void handleActivate()}
                disabled={activating || !key.trim()}
                className={`h-11 shrink-0 rounded-lg bg-[var(--color-accent)] px-4 text-sm font-medium text-[var(--color-accent-on)] transition-colors hover:bg-[var(--color-accent-hover)] disabled:opacity-50 disabled:cursor-not-allowed ${FOCUS_RING}`}
              >
                {activating ? "Activating..." : "Activate"}
              </button>
            </div>
            {activateMsg && (
              <p className={`mt-3 text-sm ${activateMsg.ok ? "text-[var(--color-status-ok)]" : "text-[var(--color-severity-critical)]"}`}>
                {activateMsg.text}
              </p>
            )}
          </div>
        </div>

        {/* Resource Usage */}
        <div>
          <p className={sectionHeadingClass}>Resource Usage</p>
          <div className="rounded-2xl border border-[var(--color-border)] bg-[var(--color-surface)] divide-y divide-[var(--color-border)]">
            {([
              { label: "Users", used: displayUsage.users, max: displayLimits.max_users },
              { label: "Source Connections", used: displayUsage.source_connections, max: displayLimits.max_source_connections },
              { label: "Remote Runners", used: displayUsage.remote_runners, max: displayLimits.max_remote_runners },
              { label: "Custom Roles", used: displayUsage.custom_roles, max: displayLimits.custom_roles === false ? 0 : null },
              { label: "Teams", used: displayUsage.teams, max: displayLimits.teams === false ? 0 : null },
            ] as { label: string; used: number; max: number | null }[]).map(({ label, used, max }) => {
              const isUnlimited = max == null
              const isDisabled = max === 0
              const pct = isUnlimited || isDisabled ? 0 : Math.min((used / max) * 100, 100)
              const isOver = !isUnlimited && !isDisabled && used > max
              const isAtLimit = !isUnlimited && !isDisabled && used >= max
              return (
                <div key={label} className="flex items-center gap-4 px-6 py-3.5">
                  <span className="min-w-[140px] text-sm text-[var(--color-text-secondary)]">{label}</span>
                  <div className="flex flex-1 items-center gap-3">
                    {!isUnlimited && !isDisabled && (
                      <div className="h-1.5 flex-1 max-w-[200px] overflow-hidden rounded-full bg-[var(--color-surface-raised)]">
                        <div
                          className={`h-full rounded-full transition-all ${isOver || isAtLimit ? "bg-[var(--color-severity-critical)]" : "bg-[var(--color-accent)]"}`}
                          style={{ width: `${Math.min(pct, 100)}%` }}
                        />
                      </div>
                    )}
                  </div>
                  <span className="shrink-0 text-right">
                    {isDisabled ? (
                      <span className="text-xs text-[var(--color-text-tertiary)]">Locked</span>
                    ) : isUnlimited ? (
                      <span className="text-sm text-[var(--color-text-secondary)]"><span className={`font-semibold tabular-nums ${isOver ? "text-[var(--color-severity-critical)]" : "text-[var(--color-text-primary)]"}`}>{used}</span> <span className="text-xs">/ Unlimited</span></span>
                    ) : (
                      <span className={`text-sm font-semibold tabular-nums ${isOver ? "text-[var(--color-severity-critical)]" : "text-[var(--color-text-primary)]"}`}>{used}<span className="font-normal text-[var(--color-text-secondary)]"> / {max}</span></span>
                    )}
                  </span>
                </div>
              )
            })}
          </div>
        </div>

        {/* Remove license */}
        {displayLicense && (
          <div>
            <p className={sectionHeadingClass}>Remove License</p>
            <div className="rounded-2xl border border-[var(--color-border)] bg-[var(--color-surface)] px-6 py-5">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium text-[var(--color-text-primary)]">Remove current license</p>
                  <p className="mt-0.5 text-xs text-[var(--color-text-secondary)]">
                    Reverts your plan to the Community tier.
                  </p>
                </div>
                <button
                  type="button"
                  onClick={() => setShowRemoveConfirm(true)}
                  disabled={removing}
                  className={`rounded-lg border border-[var(--color-severity-critical)]/20 px-4 py-2 text-sm font-medium text-[var(--color-severity-critical)] transition-colors hover:border-[var(--color-severity-critical)]/30 hover:bg-[var(--color-severity-critical)]/5 disabled:opacity-50 ${FOCUS_RING}`}
                >
                  {removing ? "Removing..." : "Remove License"}
                </button>
              </div>
            </div>
          </div>
        )}

        {/* Argus add-on */}
        <div>
          <p className={sectionHeadingClass}>Add-ons</p>
          <div className={`rounded-2xl border px-6 py-5 ${hasArgus ? "border-[var(--color-argus-border)] bg-[var(--color-argus-subtle)]" : "border-[var(--color-border)] bg-[var(--color-surface)]"}`}>
            <div className="flex items-start justify-between gap-4">
              <div>
                <div className="flex items-center gap-2">
                  <span className="text-sm font-semibold text-[var(--color-text-primary)]">Blu3Raven Argus</span>
                  {hasArgus ? (
                    <span className="rounded-full bg-[var(--color-argus-subtle)] px-2 py-0.5 text-[11px] font-semibold text-[var(--color-argus)]">Active</span>
                  ) : (
                    <span className="rounded-full bg-[var(--color-surface-raised)] px-2 py-0.5 text-[11px] font-semibold text-[var(--color-text-tertiary)]">Not activated</span>
                  )}
                </div>
                <p className="mt-1 text-sm text-[var(--color-text-secondary)]">
                  AI-powered threat intelligence with EPSS scores, exploit availability, and advisory enrichment. Works with any plan.
                </p>
              </div>
              {hasArgus ? (
                <Link
                  href="/settings/dependencies"
                  className={`shrink-0 rounded-lg border border-[var(--color-border)] px-3 py-1.5 text-xs font-semibold text-[var(--color-text-primary)] transition-colors hover:bg-[var(--color-surface-raised)] ${FOCUS_RING}`}
                >
                  Configure
                </Link>
              ) : null}
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
