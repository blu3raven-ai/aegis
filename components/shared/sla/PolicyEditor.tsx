"use client"

import { useState } from "react"
import type { SlaPolicy, UpdateSlaPolicyPayload } from "@/lib/client/sla-api"

const SEVERITY_ORDER: SlaPolicy["severity"][] = ["critical", "high", "medium", "low"]

const SEV_COLORS: Record<SlaPolicy["severity"], string> = {
  critical: "text-[var(--color-severity-critical)]",
  high: "text-[var(--color-severity-high)]",
  medium: "text-[var(--color-severity-medium)]",
  low: "text-[var(--color-severity-low)]",
}

interface PolicyRowState {
  deadline_days: number
  enabled: boolean
  saving: boolean
  error: string | null
  saved: boolean
}

interface PolicyEditorProps {
  policies: SlaPolicy[]
  onSave: (severity: string, payload: UpdateSlaPolicyPayload) => Promise<void>
}

export function PolicyEditor({ policies, onSave }: PolicyEditorProps) {
  const initialState = Object.fromEntries(
    policies.map((p) => [
      p.severity,
      { deadline_days: p.deadline_days, enabled: p.enabled, saving: false, error: null, saved: false },
    ]),
  ) as Record<string, PolicyRowState>

  const [rows, setRows] = useState<Record<string, PolicyRowState>>(initialState)

  function setRow(severity: string, patch: Partial<PolicyRowState>) {
    setRows((prev) => ({ ...prev, [severity]: { ...prev[severity], ...patch } }))
  }

  async function handleSave(severity: string) {
    const row = rows[severity]
    if (!row) return
    if (row.deadline_days <= 0) {
      setRow(severity, { error: "Deadline must be at least 1 day." })
      return
    }
    setRow(severity, { saving: true, error: null, saved: false })
    try {
      await onSave(severity, { deadline_days: row.deadline_days, enabled: row.enabled })
      setRow(severity, { saving: false, saved: true })
      // Clear the saved indicator after 2 s
      setTimeout(() => setRow(severity, { saved: false }), 2000)
    } catch (err) {
      const msg = err instanceof Error ? err.message : "Failed to save"
      setRow(severity, { saving: false, error: msg })
    }
  }

  const sorted = SEVERITY_ORDER.map((sev) => ({ sev, row: rows[sev] })).filter((x) => x.row)

  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b border-[var(--color-border)]">
            <th className="py-2 pr-4 text-left text-[11px] font-semibold uppercase tracking-[0.14em] text-[var(--color-text-secondary)]">
              Severity
            </th>
            <th className="py-2 pr-4 text-left text-[11px] font-semibold uppercase tracking-[0.14em] text-[var(--color-text-secondary)]">
              Deadline (days)
            </th>
            <th className="py-2 pr-4 text-left text-[11px] font-semibold uppercase tracking-[0.14em] text-[var(--color-text-secondary)]">
              Enabled
            </th>
            <th className="py-2 text-right text-[11px] font-semibold uppercase tracking-[0.14em] text-[var(--color-text-secondary)]" />
          </tr>
        </thead>
        <tbody className="divide-y divide-[var(--color-border)]">
          {sorted.map(({ sev, row }) => (
            <tr key={sev}>
              <td className="py-3 pr-4">
                <span className={`font-semibold capitalize ${SEV_COLORS[sev as SlaPolicy["severity"]]}`}>{sev}</span>
              </td>
              <td className="py-3 pr-4">
                <input
                  type="number"
                  min={1}
                  value={row.deadline_days}
                  onChange={(e) => setRow(sev, { deadline_days: Number(e.target.value), error: null, saved: false })}
                  className="w-24 rounded-lg border border-[var(--color-border)] bg-[var(--color-surface)] px-3 py-1.5 text-sm text-[var(--color-text-primary)] focus:border-[var(--color-accent)] focus:outline-none focus:ring-1 focus:ring-[var(--color-accent)]"
                  aria-label={`${sev} deadline days`}
                />
              </td>
              <td className="py-3 pr-4">
                <button
                  type="button"
                  role="switch"
                  aria-checked={row.enabled}
                  onClick={() => setRow(sev, { enabled: !row.enabled, saved: false })}
                  className={`relative inline-flex h-5 w-9 items-center rounded-full transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)] ${
                    row.enabled ? "bg-[var(--color-accent)]" : "bg-[var(--color-surface-raised)]"
                  }`}
                  aria-label={`Toggle ${sev} policy`}
                >
                  <span
                    className={`inline-block h-3.5 w-3.5 transform rounded-full bg-white shadow transition-transform ${
                      row.enabled ? "translate-x-4" : "translate-x-1"
                    }`}
                  />
                </button>
              </td>
              <td className="py-3 text-right">
                <div className="flex items-center justify-end gap-2">
                  {row.error && (
                    <span className="text-xs text-[var(--color-severity-critical)]">{row.error}</span>
                  )}
                  {row.saved && (
                    <span className="text-xs text-[var(--color-status-ok)]">Saved</span>
                  )}
                  <button
                    type="button"
                    onClick={() => handleSave(sev)}
                    disabled={row.saving}
                    className="rounded-lg border border-[var(--color-border)] bg-[var(--color-surface)] px-3 py-1.5 text-xs font-semibold text-[var(--color-text-primary)] transition-colors hover:bg-[var(--color-surface-raised)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)] disabled:opacity-50"
                  >
                    {row.saving ? "Saving…" : "Save"}
                  </button>
                </div>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
