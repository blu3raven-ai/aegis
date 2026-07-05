"use client"

import { useState } from "react"
import type { SlaPolicy, UpdateSlaPolicyPayload } from "@/lib/client/sla-api"
import { Button } from "@/components/ui/Button"
import { Input } from "@/components/ui/Input"
import { Table, Thead, Tbody, Tr, Th, Td } from "@/components/ui/Table"

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
      <Table>
        <Thead className="bg-transparent">
          <Tr>
            <Th className="px-0 pr-4 pt-0 pb-2">Severity</Th>
            <Th className="px-0 pr-4 pt-0 pb-2">Deadline (days)</Th>
            <Th className="px-0 pr-4 pt-0 pb-2">Enabled</Th>
            <Th className="px-0 pt-0 pb-2 text-right" />
          </Tr>
        </Thead>
        <Tbody>
          {sorted.map(({ sev, row }) => (
            <Tr key={sev}>
              <Td className="px-0 py-3 pr-4">
                <span className={`font-semibold capitalize ${SEV_COLORS[sev as SlaPolicy["severity"]]}`}>{sev}</span>
              </Td>
              <Td className="px-0 py-3 pr-4">
                <Input
                  size="sm"
                  type="number"
                  min={1}
                  value={row.deadline_days}
                  onChange={(e) => setRow(sev, { deadline_days: Number(e.target.value), error: null, saved: false })}
                  className="w-24"
                  aria-label={`${sev} deadline days`}
                />
              </Td>
              <Td className="px-0 py-3 pr-4">
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
              </Td>
              <Td className="px-0 py-3 text-right">
                <div className="flex items-center justify-end gap-2">
                  {row.error && (
                    <span className="text-xs text-[var(--color-severity-critical)]">{row.error}</span>
                  )}
                  {row.saved && (
                    <span className="text-xs text-[var(--color-status-ok)]">Saved</span>
                  )}
                  <Button
                    variant="secondary"
                    size="sm"
                    onClick={() => handleSave(sev)}
                    disabled={row.saving}
                    isLoading={row.saving}
                  >
                    {row.saving ? "Saving…" : "Save"}
                  </Button>
                </div>
              </Td>
            </Tr>
          ))}
        </Tbody>
      </Table>
    </div>
  )
}
