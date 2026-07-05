"use client"

import { useCallback, useEffect, useRef, useState } from "react"
import { listRunners, type RunnerStatus } from "@/lib/client/fleet-api"
import { RunnerStatusBadge } from "./RunnerStatusBadge"
import { ScannerTypesBadgeList } from "./ScannerTypesBadgeList"
import { EmptyFleetState } from "./EmptyFleetState"

const REFRESH_INTERVAL_MS = 10_000

type LoadState = "loading" | "ok" | "error"

function TableHeader() {
  const th = "px-4 py-3 text-left text-2xs font-semibold uppercase tracking-[0.14em] text-[var(--color-text-secondary)]"
  return (
    <thead>
      <tr className="border-b border-[var(--color-border)]">
        <th className={th}>Agent</th>
        <th className={th}>Hostname</th>
        <th className={th}>Scanner types</th>
        <th className={`${th} text-right`}>In flight</th>
        <th className={`${th} text-right`}>Total processed</th>
        <th className={th}>Status</th>
      </tr>
    </thead>
  )
}

function RunnerRow({ runner }: { runner: RunnerStatus }) {
  return (
    <tr className="border-b border-[var(--color-border)] last:border-b-0 transition-colors hover:bg-[var(--color-surface-raised)]">
      <td className="px-4 py-3 font-mono text-xs text-[var(--color-text-primary)]">
        {runner.agent_id}
      </td>
      <td className="px-4 py-3 text-sm text-[var(--color-text-secondary)]">
        {runner.hostname || "—"}
      </td>
      <td className="px-4 py-3">
        <ScannerTypesBadgeList types={runner.scanner_types} />
      </td>
      <td className="px-4 py-3 text-right font-mono text-sm tabular-nums text-[var(--color-text-primary)]">
        {runner.in_flight_jobs}
      </td>
      <td className="px-4 py-3 text-right font-mono text-sm tabular-nums text-[var(--color-text-secondary)]">
        {runner.processed_total.toLocaleString()}
      </td>
      <td className="px-4 py-3">
        <RunnerStatusBadge status={runner.status} />
      </td>
    </tr>
  )
}

export function RunnersTable() {
  const [runners, setRunners] = useState<RunnerStatus[]>([])
  const [loadState, setLoadState] = useState<LoadState>("loading")
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null)

  const load = useCallback(async () => {
    try {
      const data = await listRunners()
      setRunners(data)
      setLoadState("ok")
    } catch {
      setLoadState("error")
    }
  }, [])

  useEffect(() => {
    void load()
    intervalRef.current = setInterval(() => { void load() }, REFRESH_INTERVAL_MS)
    return () => {
      if (intervalRef.current) clearInterval(intervalRef.current)
    }
  }, [load])

  if (loadState === "loading") {
    return (
      <div className="flex items-center justify-center py-12 text-sm text-[var(--color-text-secondary)]">
        Loading runners…
      </div>
    )
  }

  if (loadState === "error") {
    return (
      <div className="flex items-center justify-center py-12 text-sm text-[var(--color-severity-critical)]">
        Failed to load runner fleet. Check that Redis is reachable.
      </div>
    )
  }

  if (runners.length === 0) {
    return <EmptyFleetState />
  }

  return (
    <div className="overflow-hidden rounded-xl border border-[var(--color-border)] bg-[var(--color-surface)] shadow-[var(--shadow-card)]">
      <div className="overflow-x-auto">
        <table className="w-full min-w-[640px] border-collapse text-sm">
          <TableHeader />
          <tbody>
            {runners.map((r) => (
              <RunnerRow key={r.agent_id} runner={r} />
            ))}
          </tbody>
        </table>
      </div>
      <div className="border-t border-[var(--color-border)] px-4 py-2 text-right">
        <span className="text-2xs text-[var(--color-text-tertiary)]">
          Auto-refreshes every 10 s
        </span>
      </div>
    </div>
  )
}
