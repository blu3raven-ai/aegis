"use client"

import { useState } from "react"
import { Button } from "@/components/ui/Button"
import { FormField } from "@/components/ui/FormField"
import { Input } from "@/components/ui/Input"
import { SegmentedControl } from "@/components/ui/SegmentedControl"
import { Sheet } from "@/components/ui/Sheet"
import { Textarea } from "@/components/ui/Textarea"
import { ApiClientError } from "@/lib/client/api-client.types"
import {
  createFrameworkWithControls,
  type CreateControlBody,
} from "@/lib/client/compliance-api"
import { FRAMEWORK_TEMPLATES } from "./framework-templates"

interface Props {
  open: boolean
  onClose: () => void
  onCreated: () => void
  /** Framework ids already tracked — their templates are hidden from the picker. */
  trackedIds?: string[]
}

interface DraftControl {
  control_id: string
  title: string
  description: string
  category: string
}

const EMPTY_CONTROL: DraftControl = {
  control_id: "",
  title: "",
  description: "",
  category: "",
}

function readErrorMessage(err: unknown, fallback: string): string {
  if (err instanceof ApiClientError) {
    const body = err.body as { detail?: string; error?: string } | null
    return body?.detail ?? body?.error ?? `${fallback} (HTTP ${err.status})`
  }
  return err instanceof Error ? err.message : fallback
}

// Picker options: a blank custom framework plus each prebuilt starter catalog.
const TEMPLATE_OPTIONS = [
  { id: "blank", label: "Blank" },
  ...FRAMEWORK_TEMPLATES.map((t) => ({
    id: t.id,
    label: t.short,
    count: t.controls.length,
  })),
] as const

type TemplateOptionId = (typeof TEMPLATE_OPTIONS)[number]["id"]

export function AddFrameworkModal({ open, onClose, onCreated, trackedIds = [] }: Props) {
  const [templateId, setTemplateId] = useState<TemplateOptionId>("blank")
  // Hide catalogs that are already tracked (adding a duplicate id would fail).
  const templateOptions = TEMPLATE_OPTIONS.filter(
    (o) => o.id === "blank" || !trackedIds.includes(o.id),
  )
  const hasTemplateChoices = templateOptions.length > 1
  const [id, setId] = useState("")
  const [label, setLabel] = useState("")
  const [description, setDescription] = useState("")
  const [controls, setControls] = useState<DraftControl[]>([{ ...EMPTY_CONTROL }])
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState<string | null>(null)

  // Selecting a starter catalog prefills every field; "Blank" clears back to a
  // single empty control. The framework id and control ids match what the
  // finding auto-mapper emits, so adding a template surfaces existing mappings.
  function applyTemplate(next: TemplateOptionId) {
    setTemplateId(next)
    setError(null)
    const template = FRAMEWORK_TEMPLATES.find((t) => t.id === next)
    if (!template) {
      setId("")
      setLabel("")
      setDescription("")
      setControls([{ ...EMPTY_CONTROL }])
      return
    }
    setId(template.id)
    setLabel(template.label)
    setDescription(template.description)
    setControls(template.controls.map((c) => ({ ...c })))
  }

  function updateControl(index: number, patch: Partial<DraftControl>) {
    setControls((prev) => prev.map((c, i) => (i === index ? { ...c, ...patch } : c)))
  }

  function addControl() {
    setControls((prev) => [...prev, { ...EMPTY_CONTROL }])
  }

  function removeControl(index: number) {
    setControls((prev) => (prev.length <= 1 ? prev : prev.filter((_, i) => i !== index)))
  }

  function reset() {
    setTemplateId("blank")
    setId("")
    setLabel("")
    setDescription("")
    setControls([{ ...EMPTY_CONTROL }])
    setError(null)
    setSubmitting(false)
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    setSubmitting(true)
    setError(null)

    const trimmedId = id.trim()
    const trimmedLabel = label.trim()
    if (!trimmedId || !trimmedLabel) {
      setError("Framework ID and label are required")
      setSubmitting(false)
      return
    }

    const validControls = controls
      .map((c): CreateControlBody | null => {
        const cid = c.control_id.trim()
        const ctitle = c.title.trim()
        if (!cid || !ctitle) return null
        return {
          control_id: cid,
          title: ctitle,
          description: c.description.trim() || null,
          category: c.category.trim() || null,
        }
      })
      .filter((c): c is CreateControlBody => c !== null)

    try {
      await createFrameworkWithControls({
        id: trimmedId,
        label: trimmedLabel,
        description: description.trim() || null,
        controls: validControls,
      })
      reset()
      onCreated()
    } catch (err) {
      setError(readErrorMessage(err, "Failed to create framework"))
      setSubmitting(false)
    }
  }

  function handleClose() {
    if (submitting) return
    reset()
    onClose()
  }

  return (
    <Sheet
      open={open}
      onClose={handleClose}
      title="New compliance framework"
      variant="modal"
      description="Start from a prebuilt catalog or define your own. You can edit every control before saving."
      size="lg"
    >
      <form onSubmit={handleSubmit} className="space-y-4 text-sm">
          {hasTemplateChoices && (
            <div className="space-y-2">
              <div className="flex items-center justify-between gap-3">
                <span className="text-2xs font-semibold uppercase tracking-[0.14em] text-[var(--color-text-tertiary)]">
                  Start from a template
                </span>
                <SegmentedControl
                  options={templateOptions}
                  value={templateId}
                  onChange={applyTemplate}
                  ariaLabel="Framework template"
                />
              </div>
              <p className="text-xs text-[var(--color-text-secondary)]">
                {templateId === "blank"
                  ? "Define a custom framework and its controls by hand."
                  : `Prefilled with ${controls.length} controls mapped by scanners. Edit any field before saving.`}
              </p>
            </div>
          )}

          <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
            <FormField label="Framework ID" htmlFor="framework-id" required>
              <Input
                id="framework-id"
                size="sm"
                required
                value={id}
                onChange={(e) => setId(e.target.value)}
                placeholder="acme-2026"
                pattern="[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?"
                title="lowercase letters, digits, hyphens; 1–64 chars"
                className="font-mono"
              />
            </FormField>
            <FormField label="Label" htmlFor="framework-label" required>
              <Input
                id="framework-label"
                size="sm"
                required
                value={label}
                onChange={(e) => setLabel(e.target.value)}
                placeholder="ACME 2026"
              />
            </FormField>
          </div>

          <FormField label="Description (optional)" htmlFor="framework-description">
            <Textarea
              id="framework-description"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              rows={2}
            />
          </FormField>

          <div>
            <div className="mb-2 flex items-center justify-between">
              <span className="text-xs font-medium text-[var(--color-text-secondary)]">
                Controls
              </span>
              <Button variant="ghost" size="xs" type="button" onClick={addControl}>
                + Add control
              </Button>
            </div>
            <div className="space-y-2">
              {controls.map((c, i) => (
                <div
                  key={i}
                  className="grid grid-cols-1 gap-2 rounded-md border border-[var(--color-border)] bg-[var(--color-surface-raised)] p-2 sm:grid-cols-12"
                >
                  <Input
                    size="sm"
                    value={c.control_id}
                    onChange={(e) => updateControl(i, { control_id: e.target.value })}
                    placeholder="A.1"
                    aria-label="Control ID"
                    className="col-span-2 font-mono"
                  />
                  <Input
                    size="sm"
                    value={c.title}
                    onChange={(e) => updateControl(i, { title: e.target.value })}
                    placeholder="Access controls"
                    aria-label="Control title"
                    className="col-span-4"
                  />
                  <Input
                    size="sm"
                    value={c.category}
                    onChange={(e) => updateControl(i, { category: e.target.value })}
                    placeholder="Category"
                    aria-label="Control category"
                    className="col-span-2"
                  />
                  <Input
                    size="sm"
                    value={c.description}
                    onChange={(e) => updateControl(i, { description: e.target.value })}
                    placeholder="Description"
                    aria-label="Control description"
                    className="col-span-3"
                  />
                  <div className="col-span-1 flex justify-center">
                    <Button
                      variant="ghost"
                      size="xs"
                      iconOnly
                      onClick={() => removeControl(i)}
                      disabled={controls.length <= 1}
                      aria-label="Remove control"
                      className="hover:text-[var(--color-severity-critical-text)]"
                    >
                      ×
                    </Button>
                  </div>
                </div>
              ))}
            </div>
            <p className="mt-1 text-2xs text-[var(--color-text-secondary)]">
              Rows with empty ID or title are skipped on save.
            </p>
          </div>

          {error && (
            <p
              role="alert"
              className="rounded-md border border-[var(--color-severity-critical)]/40 bg-[var(--color-severity-critical)]/5 px-3 py-2 text-xs text-[var(--color-severity-critical-text)]"
            >
              {error}
            </p>
          )}

          <div className="flex justify-end gap-2 pt-2">
            <Button
              variant="secondary"
              size="md"
              type="button"
              onClick={handleClose}
              disabled={submitting}
            >
              Cancel
            </Button>
            <Button
              variant="primary"
              size="md"
              type="submit"
              isLoading={submitting}
              disabled={submitting || !id.trim() || !label.trim()}
            >
              Create framework
            </Button>
          </div>
        </form>
    </Sheet>
  )
}
