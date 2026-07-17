"use client"

import { useEffect, useState } from "react"
import { Button } from "@/components/ui/Button"
import { Card } from "@/components/ui/Card"
import { FilterChip } from "@/components/ui/FilterChip"
import { Input } from "@/components/ui/Input"
import { FindingAssigneePicker } from "@/components/shared/findings/FindingAssigneePicker"
import { useHasPermission } from "@/lib/client/use-permission"
import { getActiveTimeZone } from "@/lib/client/active-timezone"
import {
  upsertControlAssessment,
  type ControlSummaryItem,
  type ManualControlStatus,
} from "@/lib/client/compliance-api"

type StatusChoice = ManualControlStatus | "auto"

// Auto = fall back to the finding-derived status; the rest are explicit
// analyst attestations that override it.
const STATUS_OPTIONS: { id: StatusChoice; label: string }[] = [
  { id: "auto", label: "Auto (from findings)" },
  { id: "compliant", label: "Compliant" },
  { id: "in_progress", label: "In progress" },
  { id: "non_compliant", label: "Non-compliant" },
  { id: "not_applicable", label: "Not applicable" },
]

function formatAssessedAt(iso: string | null): string {
  if (!iso) return ""
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return ""
  return d.toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric", timeZone: getActiveTimeZone() })
}

// Only http(s) URLs are safe to render as a clickable link; anything else
// (javascript:, data:, etc.) is shown as inert text so it can't be navigated to.
function safeHttpUrl(u: string | null): string | null {
  if (!u) return null
  try {
    const p = new URL(u)
    return p.protocol === "http:" || p.protocol === "https:" ? u : null
  } catch {
    return null
  }
}

interface AttestationPanelProps {
  framework: string
  controlId: string
  assessment: ControlSummaryItem | null
  onSaved: () => void
}

export function AttestationPanel({ framework, controlId, assessment, onSaved }: AttestationPanelProps) {
  const { allowed: canManage } = useHasPermission("manage_settings")

  const initialStatus: StatusChoice = assessment?.manual_status ?? "auto"
  const [status, setStatus] = useState<StatusChoice>(initialStatus)
  const [note, setNote] = useState(assessment?.evidence_note ?? "")
  const [evidenceUrl, setEvidenceUrl] = useState(assessment?.evidence_url ?? "")
  const [ownerId, setOwnerId] = useState<string | null>(assessment?.owner_user_id ?? null)
  const [dueDate, setDueDate] = useState(assessment?.due_date ?? "")
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [savedTick, setSavedTick] = useState(false)

  // Reseed when the loaded assessment changes (e.g. after a save + reload).
  useEffect(() => {
    setStatus(assessment?.manual_status ?? "auto")
    setNote(assessment?.evidence_note ?? "")
    setEvidenceUrl(assessment?.evidence_url ?? "")
    setOwnerId(assessment?.owner_user_id ?? null)
    setDueDate(assessment?.due_date ?? "")
  }, [
    assessment?.manual_status,
    assessment?.evidence_note,
    assessment?.evidence_url,
    assessment?.owner_user_id,
    assessment?.due_date,
  ])

  const dirty =
    status !== (assessment?.manual_status ?? "auto") ||
    note.trim() !== (assessment?.evidence_note ?? "") ||
    evidenceUrl.trim() !== (assessment?.evidence_url ?? "") ||
    ownerId !== (assessment?.owner_user_id ?? null) ||
    dueDate !== (assessment?.due_date ?? "")

  async function handleSave() {
    setSaving(true)
    setError(null)
    try {
      await upsertControlAssessment(framework, controlId, {
        status,
        evidence_note: note.trim() || null,
        evidence_url: evidenceUrl.trim() || null,
        owner_user_id: ownerId,
        due_date: dueDate || null,
      })
      setSavedTick(true)
      window.setTimeout(() => setSavedTick(false), 1500)
      onSaved()
    } catch (e) {
      setError(e instanceof Error ? e.message : "Couldn't save attestation")
    } finally {
      setSaving(false)
    }
  }

  const assessedMeta =
    assessment?.assessed_at && assessment.manual_status
      ? `Last attested ${formatAssessedAt(assessment.assessed_at)}${
          assessment.assessed_by ? ` · ${assessment.assessed_by}` : ""
        }`
      : "Not yet attested — status is derived from open findings."

  const statusLabel = STATUS_OPTIONS.find((o) => o.id === assessment?.manual_status)?.label

  const savedEvidenceUrl = assessment?.evidence_url ?? null
  const savedEvidenceLink = safeHttpUrl(savedEvidenceUrl)

  return (
    <Card padding="none" elevation="sm" className="rounded-md">
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-[var(--color-border)] px-5 py-3">
        <h2 className="text-base font-semibold text-[var(--color-text-primary)]">Attestation</h2>
        <div className="flex items-center gap-2">
          {assessment?.overdue && (
            <span className="rounded-full border border-[var(--color-severity-critical)] px-2 py-0.5 text-2xs font-semibold uppercase tracking-[0.14em] text-[var(--color-severity-critical-text)]">
              Overdue
            </span>
          )}
          <span className="text-xs text-[var(--color-text-secondary)]">{assessedMeta}</span>
        </div>
      </div>

      <div className="flex flex-col gap-4 px-5 py-4">
        {!canManage ? (
          <div className="flex flex-col gap-2">
            <p className="text-sm text-[var(--color-text-secondary)] break-words">
              {assessment?.manual_status && statusLabel
                ? `This control is attested as ${statusLabel}.`
                : "This control has no manual attestation."}
              {assessment?.evidence_note ? ` Evidence: ${assessment.evidence_note}` : ""}
            </p>
            {savedEvidenceUrl ? (
              savedEvidenceLink ? (
                <a
                  href={savedEvidenceLink}
                  target="_blank"
                  rel="noreferrer noopener"
                  className="break-words text-sm text-[var(--color-accent)] underline underline-offset-2 hover:no-underline"
                >
                  {savedEvidenceUrl}
                </a>
              ) : (
                <p className="break-words text-sm text-[var(--color-text-secondary)]">
                  Evidence link: {savedEvidenceUrl}
                </p>
              )
            ) : null}
            {assessment?.owner_label || assessment?.due_date ? (
              <p className="text-sm text-[var(--color-text-secondary)] break-words">
                {assessment?.owner_label ? `Owner: ${assessment.owner_label}` : ""}
                {assessment?.owner_label && assessment?.due_date ? " · " : ""}
                {assessment?.due_date ? (
                  <span className={assessment.overdue ? "text-[var(--color-severity-critical-text)]" : undefined}>
                    Due {assessment.due_date}
                    {assessment.overdue ? " (overdue)" : ""}
                  </span>
                ) : null}
              </p>
            ) : null}
          </div>
        ) : (
          <>
            <div>
              <span className="mb-2 block text-2xs font-semibold uppercase tracking-[0.14em] text-[var(--color-text-tertiary)]">
                Status
              </span>
              <div className="flex flex-wrap gap-1.5">
                {STATUS_OPTIONS.map((opt) => (
                  <FilterChip
                    key={opt.id}
                    label={opt.label}
                    active={status === opt.id}
                    onClick={() => setStatus(opt.id)}
                  />
                ))}
              </div>
            </div>

            <div>
              <label
                htmlFor="evidence-note"
                className="mb-2 block text-2xs font-semibold uppercase tracking-[0.14em] text-[var(--color-text-tertiary)]"
              >
                Evidence note
              </label>
              <textarea
                id="evidence-note"
                value={note}
                onChange={(e) => setNote(e.target.value)}
                rows={3}
                placeholder="Summarize the evidence an auditor would review (ticket, policy, review date)…"
                className="w-full resize-y rounded-md border border-[var(--color-border)] bg-[var(--color-bg-input)] px-3 py-2 text-sm text-[var(--color-text-primary)] placeholder:text-[var(--color-text-tertiary)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)]"
              />
            </div>

            <div>
              <label
                htmlFor="evidence-url"
                className="mb-2 block text-2xs font-semibold uppercase tracking-[0.14em] text-[var(--color-text-tertiary)]"
              >
                Evidence link (optional)
              </label>
              <Input
                id="evidence-url"
                type="url"
                size="sm"
                value={evidenceUrl}
                onChange={(e) => setEvidenceUrl(e.target.value)}
                placeholder="https://…"
              />
            </div>

            <div>
              <span className="mb-2 block text-2xs font-semibold uppercase tracking-[0.14em] text-[var(--color-text-tertiary)]">
                Remediation
              </span>
              <div className="flex gap-3">
                <div className="flex-1">
                  <FindingAssigneePicker
                    value={ownerId}
                    valueLabel={assessment?.owner_label ?? null}
                    onChange={setOwnerId}
                    label="Owner"
                    emptyLabel="Unassigned"
                    disabled={saving}
                    size="sm"
                  />
                </div>
                <div className="flex-1">
                  <label
                    htmlFor="due-date"
                    className="mb-1 block text-xs text-[var(--color-text-secondary)]"
                  >
                    Due date
                  </label>
                  <Input
                    id="due-date"
                    type="date"
                    size="sm"
                    value={dueDate}
                    onChange={(e) => setDueDate(e.target.value)}
                  />
                </div>
              </div>
            </div>

            <div className="flex items-center gap-3">
              <Button
                variant="primary"
                size="sm"
                disabled={!dirty || saving}
                isLoading={saving}
                onClick={() => void handleSave()}
              >
                Save attestation
              </Button>
              {savedTick && <span className="text-xs text-[var(--color-state-fixed-text)]">Saved</span>}
              {error && (
                <span role="alert" className="text-xs text-[var(--color-severity-critical-text)]">
                  {error}
                </span>
              )}
            </div>
          </>
        )}
      </div>
    </Card>
  )
}
