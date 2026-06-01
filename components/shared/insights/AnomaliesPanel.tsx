"use client"

import { useEffect, useState } from "react"

interface AnomalyEvent {
  id: string
  description: string
  detected_at: string
  severity?: string
}

function Skeleton() {
  return (
    <div className="flex flex-col gap-2 p-4 animate-pulse">
      {[...Array(3)].map((_, i) => (
        <div key={i} className="flex items-start gap-2">
          <div className="mt-1 h-1.5 w-1.5 shrink-0 rounded-full bg-[var(--color-surface-raised)]" />
          <div className="h-3 flex-1 rounded bg-[var(--color-surface-raised)]" />
        </div>
      ))}
    </div>
  )
}

function formatTime(iso: string) {
  return new Date(iso).toLocaleString("en-US", {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  })
}

interface AnomaliesPanelProps {
  orgId: string
  sinceDays: number
}

export function AnomaliesPanel({ orgId, sinceDays }: AnomaliesPanelProps) {
  const [anomalies, setAnomalies] = useState<AnomalyEvent[]>([])
  const [loading, setLoading] = useState(true)
  // Anomaly endpoint may not exist yet; treat 404 as "not enabled"
  const [notEnabled, setNotEnabled] = useState(false)

  useEffect(() => {
    setLoading(true)
    setNotEnabled(false)

    const qs = new URLSearchParams({ org_id: orgId, since_days: String(sinceDays) })
    fetch(`/api/v1/temporal/anomalies?${qs.toString()}`)
      .then(async (res) => {
        if (res.status === 404 || res.status === 501) {
          setNotEnabled(true)
          return
        }
        if (!res.ok) {
          setNotEnabled(true)
          return
        }
        const data = (await res.json()) as { anomalies?: AnomalyEvent[] } | AnomalyEvent[]
        const events = Array.isArray(data)
          ? data
          : ((data as { anomalies?: AnomalyEvent[] }).anomalies ?? [])
        setAnomalies(events)
      })
      .catch(() => setNotEnabled(true))
      .finally(() => setLoading(false))
  }, [orgId, sinceDays])

  if (loading) return <Skeleton />

  if (notEnabled || anomalies.length === 0) {
    return (
      <div className="flex min-h-[80px] items-center justify-center px-4 py-3">
        <p className="text-[12px] text-[var(--color-text-secondary)]">
          Anomaly detection enabled when correlation engine is running.
        </p>
      </div>
    )
  }

  return (
    <ul className="flex flex-col gap-1.5 py-1" role="list" aria-label="Detected anomalies">
      {anomalies.map((ev) => (
        <li key={ev.id} className="flex items-start gap-2.5">
          <span
            className="mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full bg-[var(--color-accent)]"
            aria-hidden="true"
          />
          <div className="flex flex-col gap-0.5">
            <span className="text-[12px] text-[var(--color-text-primary)]">{ev.description}</span>
            <span className="text-[11px] text-[var(--color-text-tertiary)]">{formatTime(ev.detected_at)}</span>
          </div>
        </li>
      ))}
    </ul>
  )
}
