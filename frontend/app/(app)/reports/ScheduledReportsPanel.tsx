"use client"

import { useEffect, useState } from "react"
import { Button } from "@/components/ui/Button"
import { Card } from "@/components/ui/Card"
import { FilterChip } from "@/components/ui/FilterChip"
import { FormField } from "@/components/ui/FormField"
import { Input } from "@/components/ui/Input"
import { Select } from "@/components/ui/Select"
import { Sheet } from "@/components/ui/Sheet"
import { Table, Thead, Tbody, Tr, Th, Td } from "@/components/ui/Table"
import { apiClient } from "@/lib/client/api-client"
import { listDestinations, type NotificationDestination } from "@/lib/client/destinations-api"

interface ScheduledReport {
  id: number
  name: string
  report_type: "findings" | "posture"
  format: "json" | "csv" | "pdf"
  schedule_type: "simple" | "cron"
  schedule_value: string
  filters: Record<string, unknown>
  destination_ids: number[]
  created_by: string
  enabled: boolean
  last_run_at: string | null
  last_run_status: "success" | "failed" | null
  last_run_error: string | null
  created_at: string
  updated_at: string
}

interface ListResponse {
  items: ScheduledReport[]
}

async function listSchedules(): Promise<ScheduledReport[]> {
  const data = await apiClient<ListResponse>("/api/v1/findings/reports/scheduled")
  return data.items
}

async function deleteSchedule(id: number): Promise<void> {
  await apiClient<void>(`/api/v1/findings/reports/scheduled/${id}`, { method: "DELETE" })
}

interface CreatePayload {
  name: string
  report_type: "findings" | "posture"
  format: "json" | "csv" | "pdf"
  schedule_type: "simple" | "cron"
  schedule_value: string
  filters?: Record<string, unknown>
  destination_ids: number[]
  enabled: boolean
}

async function createSchedule(payload: CreatePayload): Promise<ScheduledReport> {
  return apiClient<ScheduledReport>("/api/v1/findings/reports/scheduled", {
    method: "POST",
    body: payload,
  })
}

export function ScheduledReportsPanel() {
  const [items, setItems] = useState<ScheduledReport[] | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [showCreate, setShowCreate] = useState(false)
  const [destinations, setDestinations] = useState<NotificationDestination[]>([])

  async function refresh() {
    try {
      const fresh = await listSchedules()
      setItems(fresh)
      setError(null)
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load scheduled reports")
    }
  }

  useEffect(() => {
    void refresh()
    void listDestinations()
      .then(setDestinations)
      .catch(() => setDestinations([]))
  }, [])

  async function handleDelete(id: number) {
    if (!window.confirm("Delete this schedule? The report data is unaffected.")) return
    try {
      await deleteSchedule(id)
      setItems((prev) => prev?.filter((s) => s.id !== id) ?? null)
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to delete schedule")
    }
  }

  return (
    <Card as="section">
      <div className="mb-4 flex items-center justify-between gap-3">
        <div>
          <h2 className="text-base font-semibold text-[var(--color-text-primary)]">Scheduled reports</h2>
          <p className="mt-0.5 text-xs text-[var(--color-text-secondary)]">
            Reports run automatically and deliver to configured notification destinations.
          </p>
        </div>
        <Button variant="primary" size="sm" onClick={() => setShowCreate(true)}>
          Schedule
        </Button>
      </div>

      {error && (
        <p className="mb-3 rounded-md border border-[var(--color-severity-critical-border)] bg-[var(--color-severity-critical-subtle)] px-3 py-2 text-xs text-[var(--color-severity-critical)]">
          {error}
        </p>
      )}

      {items === null ? (
        <p className="text-sm text-[var(--color-text-secondary)]">Loading…</p>
      ) : items.length === 0 ? (
        <p className="text-sm text-[var(--color-text-secondary)]">No scheduled reports yet.</p>
      ) : (
        <Table>
          <Thead className="bg-transparent border-b-0">
            <Tr>
              <Th className="px-0 py-2">Name</Th>
              <Th className="px-0 py-2">Type</Th>
              <Th className="px-0 py-2">Format</Th>
              <Th className="px-0 py-2">Schedule</Th>
              <Th className="px-0 py-2">Last run</Th>
              <Th className="px-0 py-2 text-right" aria-label="actions" />
            </Tr>
          </Thead>
          <Tbody divided={false}>
            {items.map((s) => (
              <Tr key={s.id} className="border-t border-[var(--color-border-divider)]">
                <Td className="px-0 py-2.5">
                  <div className="font-medium text-[var(--color-text-primary)]">{s.name}</div>
                  {!s.enabled && (
                    <span className="text-2xs uppercase tracking-[0.14em] text-[var(--color-text-secondary)]">paused</span>
                  )}
                </Td>
                <Td className="px-0 py-2.5 text-[var(--color-text-secondary)]">{s.report_type}</Td>
                <Td className="px-0 py-2.5 text-[var(--color-text-secondary)]">{s.format.toUpperCase()}</Td>
                <Td className="px-0 py-2.5 text-[var(--color-text-secondary)]">
                  {s.schedule_type === "simple" ? `daily ${s.schedule_value}` : s.schedule_value}
                </Td>
                <Td className="px-0 py-2.5 text-[var(--color-text-secondary)]">
                  {s.last_run_at ? (
                    <LastRunCell at={s.last_run_at} status={s.last_run_status} error={s.last_run_error} />
                  ) : (
                    "—"
                  )}
                </Td>
                <Td className="px-0 py-2.5 text-right">
                  <Button
                    variant="ghost"
                    size="xs"
                    onClick={() => handleDelete(s.id)}
                    className="text-[var(--color-severity-critical)] hover:text-[var(--color-severity-critical)]"
                  >
                    Delete
                  </Button>
                </Td>
              </Tr>
            ))}
          </Tbody>
        </Table>
      )}

      <CreateScheduleModal
        open={showCreate}
        destinations={destinations}
        onClose={() => setShowCreate(false)}
        onCreated={() => {
          setShowCreate(false)
          void refresh()
        }}
      />
    </Card>
  )
}

function LastRunCell({
  at,
  status,
  error,
}: {
  at: string
  status: string | null
  error: string | null
}) {
  const ts = new Date(at).toLocaleString()
  if (status === "failed") {
    return (
      <span className="text-[var(--color-severity-critical)]" title={error ?? undefined}>
        failed · {ts}
      </span>
    )
  }
  return <span>{ts}</span>
}

function CreateScheduleModal({
  open,
  destinations,
  onClose,
  onCreated,
}: {
  open: boolean
  destinations: NotificationDestination[]
  onClose: () => void
  onCreated: () => void
}) {
  const [name, setName] = useState("")
  const [reportType, setReportType] = useState<"findings" | "posture">("findings")
  const [format, setFormat] = useState<"json" | "csv" | "pdf">("pdf")
  const [scheduleType, setScheduleType] = useState<"simple" | "cron">("simple")
  const [scheduleValue, setScheduleValue] = useState("09:00")
  const [destIds, setDestIds] = useState<number[]>([])
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState<string | null>(null)

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    setSubmitting(true)
    setError(null)
    try {
      // Backend rejects posture+csv; coerce if the user landed there.
      const effectiveFormat: "json" | "csv" | "pdf" =
        reportType === "posture" && format === "csv" ? "json" : format
      await createSchedule({
        name: name.trim(),
        report_type: reportType,
        format: effectiveFormat,
        schedule_type: scheduleType,
        schedule_value: scheduleValue.trim(),
        destination_ids: destIds,
        enabled: true,
      })
      onCreated()
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to create schedule")
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <Sheet
      open={open}
      onClose={onClose}
      title="New scheduled report"
      size="md"
    >
      <form onSubmit={handleSubmit} className="space-y-3 text-sm">
          <FormField label="Name" htmlFor="report-name" required>
            <Input
              id="report-name"
              size="sm"
              required
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="Weekly findings"
            />
          </FormField>

          <div className="flex gap-3">
            <FormField label="Type" htmlFor="report-type" className="flex-1">
              <Select
                id="report-type"
                size="sm"
                value={reportType}
                onChange={(e) => setReportType(e.target.value as "findings" | "posture")}
              >
                <option value="findings">findings</option>
                <option value="posture">posture</option>
              </Select>
            </FormField>
            <FormField label="Format" htmlFor="report-format" className="flex-1">
              <Select
                id="report-format"
                size="sm"
                value={format}
                onChange={(e) => setFormat(e.target.value as "json" | "csv" | "pdf")}
              >
                <option value="pdf">pdf</option>
                <option value="json">json</option>
                {reportType === "findings" && <option value="csv">csv</option>}
              </Select>
            </FormField>
          </div>

          <div className="flex gap-3">
            <FormField label="Schedule type" htmlFor="report-schedule-type" className="flex-1">
              <Select
                id="report-schedule-type"
                size="sm"
                value={scheduleType}
                onChange={(e) => setScheduleType(e.target.value as "simple" | "cron")}
              >
                <option value="simple">daily (HH:MM)</option>
                <option value="cron">cron</option>
              </Select>
            </FormField>
            <FormField
              label={scheduleType === "simple" ? "Time (UTC)" : "Cron expression"}
              htmlFor="report-schedule-value"
              className="flex-1"
              required
            >
              <Input
                id="report-schedule-value"
                size="sm"
                required
                value={scheduleValue}
                onChange={(e) => setScheduleValue(e.target.value)}
                placeholder={scheduleType === "simple" ? "09:00" : "0 9 * * 1"}
              />
            </FormField>
          </div>

          {destinations.length > 0 && (
            <div>
              <span className="text-xs font-medium text-[var(--color-text-secondary)]">Destinations</span>
              <div className="mt-1 flex flex-wrap gap-1.5">
                {destinations.map((d) => {
                  const active = destIds.includes(d.id)
                  return (
                    <FilterChip
                      key={d.id}
                      label={`${d.name} (${d.destination_type})`}
                      active={active}
                      onClick={() =>
                        setDestIds((prev) =>
                          active ? prev.filter((x) => x !== d.id) : [...prev, d.id],
                        )
                      }
                    />
                  )
                })}
              </div>
            </div>
          )}

          {error && (
            <p className="rounded-md border border-[var(--color-severity-critical-border)] bg-[var(--color-severity-critical-subtle)] px-3 py-2 text-xs text-[var(--color-severity-critical)]">
              {error}
            </p>
          )}

          <div className="mt-4 flex justify-end gap-2">
            <Button variant="secondary" size="sm" onClick={onClose}>
              Cancel
            </Button>
            <Button
              type="submit"
              variant="primary"
              size="sm"
              isLoading={submitting}
              disabled={submitting || !name.trim() || !scheduleValue.trim()}
            >
              {submitting ? "Creating…" : "Create"}
            </Button>
          </div>
        </form>
    </Sheet>
  )
}
