"use client"

import { useCallback, useEffect, useState } from "react"
import Link from "next/link"
import { RUNNERS_API } from "@/lib/shared/api-paths"
import { apiClient } from "@/lib/client/api-client.ts"
import { SaveBar } from "@/app/(app)/settings/SaveBar"
import type { Runner, RunnerDetail, RunnerJob, HeartbeatEntry } from "../types"
import { ResourceGauge } from "../ResourceGauge"
import { HeartbeatGrid } from "../HeartbeatGrid"
import { formatDate } from "@/lib/shared/utils"
import { sectionHeadingClass } from "@/lib/shared/settings-styles"

// ─── Helpers ─────────────────────────────────────────────────────────────────

function formatDuration(start: string | null, end: string | null): string {
  if (!start) return "—"
  const endMs = end ? new Date(end).getTime() : Date.now()
  const sec = Math.floor((endMs - new Date(start).getTime()) / 1000)
  if (sec < 60) return `${sec}s`
  const min = Math.floor(sec / 60)
  return `${min}m ${sec % 60}s`
}

// ─── Design tokens (matches ScopeConfigContent) ─────────────────────────────

const cardClass =
  "overflow-hidden rounded-xl border border-[var(--color-border)] bg-[var(--color-surface)]"

function SettingsRow({
  label,
  hint,
  children,
}: {
  label: string
  hint?: string
  children: React.ReactNode
}) {
  return (
    <div className="grid items-center gap-4 border-b border-[var(--color-border)] px-5 py-[18px] last:border-b-0 md:grid-cols-[280px_1fr] md:gap-5">
      <div>
        <p className="text-sm font-medium text-[var(--color-text-primary)]">{label}</p>
        {hint && <p className="mt-1 text-xs leading-relaxed text-[var(--color-text-secondary)]">{hint}</p>}
      </div>
      <div className="flex items-center justify-end md:justify-start">{children}</div>
    </div>
  )
}

// ─── Status badge ───────────────────────────────────────────────────────────

const STATUS_DOT: Record<string, string> = {
  online: "bg-[var(--color-status-ok)]",
  stale: "bg-[var(--color-state-pending)]",
  offline: "bg-[var(--color-text-tertiary)]",
  pending_approval: "bg-[var(--color-accent)]",
}

const STATUS_LABEL: Record<string, string> = {
  online: "Online",
  stale: "Stale",
  offline: "Offline",
  pending_approval: "Pending",
}

function StatusBadge({ status }: { status: string }) {
  return (
    <span className="inline-flex items-center gap-1.5 text-sm font-medium">
      <span className={`h-2 w-2 rounded-full ${STATUS_DOT[status] ?? "bg-[var(--color-text-tertiary)]"}`} />
      <span className={status === "online" ? "text-[var(--color-status-ok)]" : "text-[var(--color-text-secondary)]"}>
        {STATUS_LABEL[status] ?? status}
      </span>
    </span>
  )
}

// ─── Job status colors ──────────────────────────────────────────────────────

const JOB_STATUS_CLASS: Record<string, string> = {
  completed: "text-[var(--color-status-ok)]",
  failed: "text-[var(--color-severity-critical)]",
  running: "text-[var(--color-accent)]",
  assigned: "text-[var(--color-accent)]",
  queued: "text-[var(--color-text-tertiary)]",
  cancelled: "text-[var(--color-state-pending)]",
}

// ─── Props ──────────────────────────────────────────────────────────────────

interface Props {
  runnerId: string
  canEdit: boolean
}

// ─── Component ──────────────────────────────────────────────────────────────

export function RunnerDetailContent({ runnerId, canEdit }: Props) {
  const [loading, setLoading] = useState(true)
  const [runner, setRunner] = useState<RunnerDetail | null>(null)
  const [recentJobs, setRecentJobs] = useState<RunnerJob[]>([])
  const [heartbeats, setHeartbeats] = useState<HeartbeatEntry[]>([])

  // Settings state
  const [maxConcurrent, setMaxConcurrent] = useState(1)
  const [runnerName, setRunnerName] = useState("")
  const [saving, setSaving] = useState(false)
  const [saved, setSaved] = useState(false)

  const load = useCallback(async () => {
    try {
      const [detailData, hbData] = await Promise.allSettled([
        apiClient<{ runner: RunnerDetail; recentJobs?: RunnerJob[] }>(RUNNERS_API.detail(runnerId)),
        apiClient<{ heartbeats: HeartbeatEntry[] }>(RUNNERS_API.heartbeats(runnerId)),
      ])
      if (detailData.status === "fulfilled") {
        const data = detailData.value
        setRunner(data.runner)
        setRecentJobs(data.recentJobs || [])
        if (loading) {
          setMaxConcurrent(data.runner.maxConcurrent ?? 1)
          setRunnerName(data.runner.name ?? "")
        }
      }
      if (hbData.status === "fulfilled") {
        setHeartbeats(hbData.value.heartbeats || [])
      }
    } catch { /* ignore */ }
    setLoading(false)
  }, [runnerId, loading])

  useEffect(() => {
    void load()
    const interval = setInterval(() => void load(), 10_000)
    return () => clearInterval(interval)
  }, [load])

  async function handleSave() {
    setSaving(true)
    try {
      await apiClient(RUNNERS_API.settings(runnerId), {
        method: "PATCH",
        body: { maxConcurrent, name: runnerName },
      })
      setSaved(true)
      setTimeout(() => setSaved(false), 2000)
    } catch { /* ignore */ }
    setSaving(false)
  }

  // ─── Loading ──────────────────────────────────────────────────────────────

  if (loading) {
    return (
      <div className="space-y-6">
        <div className="h-4 w-40 animate-pulse rounded bg-[var(--color-surface-raised)]" />
        <div className="space-y-2">
          <div className="h-7 w-64 animate-pulse rounded bg-[var(--color-surface-raised)]" />
          <div className="h-4 w-48 animate-pulse rounded bg-[var(--color-surface-raised)]" />
        </div>
        <div className="h-48 animate-pulse rounded-xl bg-[var(--color-surface-raised)]" />
      </div>
    )
  }

  if (!runner) {
    return (
      <div className="space-y-6">
        <Link href="/settings/runners" className="inline-flex items-center gap-1.5 text-sm text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)] hover:underline">
          <ChevronLeft /> Back to Runners
        </Link>
        <div className="rounded-lg border border-[var(--color-severity-critical-border)] bg-[var(--color-severity-critical-subtle)] px-4 py-3 text-sm text-[var(--color-severity-critical)]">
          Runner not found
        </div>
      </div>
    )
  }

  const platform = runner.os
    ? `${runner.os.charAt(0).toUpperCase() + runner.os.slice(1)} / ${runner.arch}`
    : null
  const completedCount = recentJobs.filter((j) => j.status === "completed").length
  const failedCount = recentJobs.filter((j) => j.status === "failed").length
  const lastPing = runner.lastHeartbeatAt
    ? Math.floor((Date.now() - new Date(runner.lastHeartbeatAt).getTime()) / 1000)
    : null

  return (
    <div className="space-y-8">
      {/* Back link */}
      <Link
        href="/settings/runners"
        className="inline-flex items-center gap-1.5 text-sm text-[var(--color-text-secondary)] transition-colors hover:text-[var(--color-text-primary)] hover:underline"
      >
        <ChevronLeft /> Back to Runners
      </Link>

      {/* Header */}
      <div className="flex items-start justify-between gap-4">
        <div>
          <h2 className="text-base font-semibold text-[var(--color-text-primary)]">
            {runner.name}
          </h2>
          <p className="mt-1 text-sm text-[var(--color-text-secondary)]">
            {platform && <>{platform} &middot; </>}
            {runner.cores && <>{runner.cores} cores &middot; </>}
            Registered {formatDate(runner.registeredAt)}
          </p>
        </div>
        <StatusBadge status={runner.status} />
      </div>

      {/* ── Connection ─────────────────────────────────────────────────────── */}
      <div>
        <p className={sectionHeadingClass}>Connection</p>
        <div className={cardClass}>
          <SettingsRow label="Status" hint="Current connection state">
            <div className="flex items-center gap-2">
              <span className={`h-2 w-2 rounded-full ${lastPing != null && lastPing < 60 ? "bg-[var(--color-status-ok)]" : "bg-[var(--color-text-tertiary)]"}`} />
              <span className="text-sm text-[var(--color-text-primary)]" title={runner.lastHeartbeatAt ? new Date(runner.lastHeartbeatAt).toLocaleString() : ""}>
                {lastPing != null && lastPing < 60 ? "Connected" : "Disconnected"}
                {lastPing != null && ` · last ping ${lastPing}s ago`}
              </span>
            </div>
          </SettingsRow>
          <SettingsRow label="Registered" hint="When the runner was first seen">
            <span className="text-sm text-[var(--color-text-primary)]">{formatDate(runner.registeredAt)}</span>
          </SettingsRow>
        </div>
      </div>

      {/* ── System Resources ───────────────────────────────────────────────── */}
      <div>
        <p className={sectionHeadingClass}>System Resources</p>
        <div className={`${cardClass} p-5`}>
          <div className="space-y-3">
            <ResourceGauge label="CPU" percent={runner.cpuPercent} />
            <ResourceGauge
              label="Memory"
              percent={runner.memoryTotalGb ? (runner.memoryUsedGb! / runner.memoryTotalGb) * 100 : null}
              detail={runner.memoryTotalGb ? `${Math.round(runner.memoryUsedGb!)} / ${Math.round(runner.memoryTotalGb)} GB` : undefined}
            />
            <ResourceGauge
              label="Disk"
              percent={runner.diskTotalGb ? (runner.diskUsedGb! / runner.diskTotalGb) * 100 : null}
              detail={runner.diskTotalGb ? `${Math.round(runner.diskUsedGb!)} / ${Math.round(runner.diskTotalGb)} GB` : undefined}
            />
          </div>
        </div>
      </div>

      {/* ── Heartbeat History ──────────────────────────────────────────────── */}
      <div>
        <p className={sectionHeadingClass}>Heartbeat History (last 1h)</p>
        <div className={`${cardClass} p-5`}>
          <HeartbeatGrid heartbeats={heartbeats} />
        </div>
      </div>

      {/* ── Recent Jobs ────────────────────────────────────────────────────── */}
      {recentJobs.length > 0 && (
        <div>
          <p className={sectionHeadingClass}>Recent Jobs</p>
          <div className={`${cardClass} overflow-x-auto`}>
            <table className="w-full text-left text-xs">
              <thead className="border-b border-[var(--color-border)] bg-[var(--color-surface-raised)]">
                <tr>
                  <th className="px-4 py-2.5 font-semibold text-[var(--color-text-secondary)]">Tool</th>
                  <th className="px-4 py-2.5 font-semibold text-[var(--color-text-secondary)]">Org</th>
                  <th className="px-4 py-2.5 font-semibold text-[var(--color-text-secondary)]">Status</th>
                  <th className="px-4 py-2.5 font-semibold text-[var(--color-text-secondary)]">Duration</th>
                </tr>
              </thead>
              <tbody>
                {recentJobs.slice(0, 10).map((job) => (
                  <tr key={job.id} className="border-b border-[var(--color-border)] last:border-0">
                    <td className="px-4 py-2.5 text-[var(--color-text-primary)]">{job.jobType}</td>
                    <td className="px-4 py-2.5 text-[var(--color-text-secondary)]">{job.org}</td>
                    <td className={`px-4 py-2.5 font-medium ${JOB_STATUS_CLASS[job.status] ?? "text-[var(--color-text-tertiary)]"}`}>
                      {job.status}
                    </td>
                    <td className="px-4 py-2.5 tabular-nums text-[var(--color-text-secondary)]">
                      {formatDuration(job.startedAt, job.completedAt)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* ── Settings ───────────────────────────────────────────────────────── */}
      {canEdit && (
        <div>
          <p className={sectionHeadingClass}>Settings</p>
          <div className={cardClass}>
            <SettingsRow label="Concurrent scan limit" hint="Maximum scanner containers that can run simultaneously on this runner.">
              <div className="space-y-3">
                <div className="flex gap-2">
                  {[1, 2, 3, 4, 5].map((n) => (
                    <button
                      key={n}
                      type="button"
                      onClick={() => setMaxConcurrent(n)}
                      className={`rounded-lg border px-4 py-2 text-sm font-medium transition-colors ${
                        maxConcurrent === n
                          ? "border-[var(--color-accent)] bg-[var(--color-accent-subtle)] text-[var(--color-accent)]"
                          : "border-[var(--color-border)] text-[var(--color-text-secondary)] hover:border-[var(--color-text-secondary)]"
                      }`}
                    >
                      {n}
                    </button>
                  ))}
                </div>
              </div>
            </SettingsRow>
            <SettingsRow label="Runner name" hint="Display name for this runner.">
              <input
                type="text"
                value={runnerName}
                onChange={(e) => setRunnerName(e.target.value)}
                className="w-full max-w-xs rounded-lg border border-[var(--color-border)] bg-[var(--color-surface)] px-3 py-2 text-sm text-[var(--color-text-primary)] focus:outline-none focus:ring-2 focus:ring-[var(--color-accent)]/30"
              />
            </SettingsRow>
          </div>
        </div>
      )}

      {/* Sticky save bar */}
      {canEdit && (
        <SaveBar
          dirty={runner != null && (maxConcurrent !== (runner.maxConcurrent ?? 1) || runnerName !== (runner.name ?? ""))}
          saved={saved}
          onSave={handleSave}
          onDiscard={() => {
            if (runner) {
              setMaxConcurrent(runner.maxConcurrent ?? 1)
              setRunnerName(runner.name ?? "")
            }
          }}
          saving={saving}
        />
      )}
    </div>
  )
}

function ChevronLeft() {
  return (
    <svg className="h-3.5 w-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <polyline points="15 18 9 12 15 6" />
    </svg>
  )
}
