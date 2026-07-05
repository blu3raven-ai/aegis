"use client"

/**
 * Modal for creating and editing rules in the two interactive
 * categories: SLA policies and scanner coverage.
 *
 * Wraps a structured form: name, description, conditions (recursive),
 * a per-category action editor, and meta (priority + enabled). Owns
 * end-to-end submit validation so the backend never receives an
 * obviously invalid payload. The modal dispatches by category for
 * defaults, action shape, action editor, field schema, validation,
 * and title — everything outside the action is shared.
 *
 * Structural patterns (backdrop, header, footer, field styling) were
 * copied from the notification routing rule editor and are allowed
 * to diverge as the two surfaces evolve.
 */

import { useEffect, useState } from "react"
import type { Condition } from "@/lib/rules-engine/conditions"
import { ConditionBuilder } from "@/components/shared/rules-engine/ConditionBuilder"
import {
  SLA_RULE_FIELDS,
  SCANNER_COVERAGE_RULE_FIELDS,
  AUTO_DISMISS_RULE_FIELDS,
  DATA_RETENTION_RULE_FIELDS,
} from "@/lib/rules-engine/field-schemas"
import {
  dryRunAndConfirm,
  isDataRetentionAction,
  isSlaAction,
  isRequireScannersAction,
  isStaleAlertAction,
  isAutoDismissAction,
  type AutoDismissAction,
  type CreateRulePayload,
  type DataRetentionAction,
  type DryRunConfirmation,
  type EditableRuleCategory,
  type RuleAction,
  type RuleSummary,
  type ScannerCoverageAction,
  type SlaAction,
  type UpdateRulePayload,
} from "@/lib/client/rules-api"
import type { NotificationDestination } from "@/lib/client/destinations-api"
import { SlaActionEditor } from "./SlaActionEditor"
import { ScannerCoverageActionEditor, REQUIRE_DEFAULT } from "./ScannerCoverageActionEditor"
import { AutoDismissActionEditor, AUTO_DISMISS_DEFAULT } from "./AutoDismissActionEditor"
import { DryRunConfirmDialog } from "./DryRunConfirmDialog"
import { Button } from "@/components/ui/Button"
import { FormField } from "@/components/ui/FormField"
import { Input } from "@/components/ui/Input"
import { Textarea } from "@/components/ui/Textarea"
import { DataRetentionActionEditor, ARCHIVE_DEFAULT } from "./DataRetentionActionEditor"
import { RulePreview } from "./RulePreview"

interface RuleEditorModalProps {
  open: boolean
  mode: "create" | "edit"
  category: EditableRuleCategory
  initialRule?: RuleSummary | null
  destinations: NotificationDestination[]
  onClose: () => void
  onSave: (payload: { create?: CreateRulePayload; update?: UpdateRulePayload }) => Promise<void>
  saving?: boolean
  saveError?: string | null
}

interface FieldErrors {
  name?: string
  description?: string
  priority?: string
  // SLA action errors
  deadline?: string
  // Scanner coverage action errors
  scannerCoverage?: {
    required_scanners?: string
    stale_after_days?: string
  }
  // Auto-dismiss action errors
  autoDismiss?: {
    reason?: string
    audit_note?: string
    rate_alarm_pct?: string
    rate_alarm_window_minutes?: string
  }
  // Data retention action errors
  dataRetention?: {
    after_days?: string
  }
}

const DEFAULT_SLA_ACTION: SlaAction = { deadline_days: 7, escalations: [] }

function defaultActionFor(cat: EditableRuleCategory): RuleAction {
  if (cat === "sla") return { ...DEFAULT_SLA_ACTION, escalations: [] }
  if (cat === "scanner_coverage") return { ...REQUIRE_DEFAULT }
  if (cat === "auto_dismiss") return { ...AUTO_DISMISS_DEFAULT }
  return { ...ARCHIVE_DEFAULT }
}

function defaultsForCreate(cat: EditableRuleCategory) {
  return {
    name: "",
    description: "",
    enabled: cat !== "auto_dismiss",
    priority: 100,
    conditions: { all: [] } as Condition,
    action: defaultActionFor(cat),
  }
}


export function RuleEditorModal({
  open,
  mode,
  category,
  initialRule,
  destinations,
  onClose,
  onSave,
  saving,
  saveError,
}: RuleEditorModalProps) {
  type Tab = "edit" | "preview"
  const [activeTab, setActiveTab] = useState<Tab>("edit")
  const [previewRefreshKey, setPreviewRefreshKey] = useState(0)

  const [name, setName] = useState("")
  const [description, setDescription] = useState("")
  const [enabled, setEnabled] = useState(true)
  const [priority, setPriority] = useState(100)
  const [conditions, setConditions] = useState<Condition>({ all: [] })
  const [action, setAction] = useState<RuleAction>(defaultActionFor(category))
  const [errors, setErrors] = useState<FieldErrors>({})

  const [dryRunOpen, setDryRunOpen] = useState(false)
  const [dryRunLoading, setDryRunLoading] = useState(false)
  const [dryRunResult, setDryRunResult] = useState<DryRunConfirmation | null>(null)
  const [dryRunError, setDryRunError] = useState<string | null>(null)

  // Typed-confirm gate for destructive `delete` data retention actions.
  // We block submit on an async modal that requires the user to type an
  // exact phrase before the rule can be saved.
  const [deleteConfirmState, setDeleteConfirmState] = useState<{
    open: boolean
    resolve?: (confirmed: boolean) => void
  }>({ open: false })
  const [deleteConfirmInput, setDeleteConfirmInput] = useState("")

  function confirmDeleteAction(): Promise<boolean> {
    setDeleteConfirmInput("")
    return new Promise((resolve) => setDeleteConfirmState({ open: true, resolve }))
  }

  function resolveDeleteConfirm(confirmed: boolean) {
    deleteConfirmState.resolve?.(confirmed)
    setDeleteConfirmState({ open: false })
    setDeleteConfirmInput("")
  }

  useEffect(() => {
    if (!open) return
    function onKeyDown(e: KeyboardEvent) {
      if (e.key === "Escape") {
        if (deleteConfirmState.open) {
          resolveDeleteConfirm(false)
          return
        }
        if (!saving) onClose()
      }
    }
    window.addEventListener("keydown", onKeyDown)
    return () => window.removeEventListener("keydown", onKeyDown)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open, saving, onClose, deleteConfirmState.open])

  useEffect(() => {
    if (!open) return
    if (mode === "edit" && initialRule) {
      setName(initialRule.name)
      setDescription(initialRule.description ?? "")
      setEnabled(initialRule.enabled)
      setPriority(initialRule.priority)
      setConditions(initialRule.conditions ?? { all: [] })
      if (category === "sla" && isSlaAction(initialRule.action)) {
        setAction({
          deadline_days: initialRule.action.deadline_days,
          escalations: [...initialRule.action.escalations],
        })
      } else if (
        category === "scanner_coverage" &&
        (isRequireScannersAction(initialRule.action) || isStaleAlertAction(initialRule.action))
      ) {
        setAction({ ...(initialRule.action as ScannerCoverageAction) })
      } else if (category === "auto_dismiss" && isAutoDismissAction(initialRule.action)) {
        setAction({ ...(initialRule.action as AutoDismissAction) })
      } else if (
        category === "data_retention" &&
        isDataRetentionAction(initialRule.action)
      ) {
        setAction({ ...(initialRule.action as DataRetentionAction) })
      } else {
        console.warn(
          "RuleEditorModal: action shape doesn't match category, using defaults",
          initialRule.action,
        )
        setAction(defaultActionFor(category))
      }
    } else {
      const d = defaultsForCreate(category)
      setName(d.name)
      setDescription(d.description)
      setEnabled(d.enabled)
      setPriority(d.priority)
      setConditions(d.conditions)
      setAction(d.action)
    }
    setErrors({})
    setActiveTab("edit")
    setPreviewRefreshKey(0)
    setDryRunOpen(false)
    setDryRunLoading(false)
    setDryRunResult(null)
    setDryRunError(null)
  }, [open, mode, initialRule, category])

  if (!open) return null

  function validateSlaAction(act: SlaAction, next: FieldErrors): void {
    if (!Number.isInteger(act.deadline_days) || act.deadline_days < 1) {
      next.deadline = "Deadline must be a positive integer"
    }

    // Escalations are a coming-soon action leg — they persist but never
    // deliver a notification, so the editor no longer lets users add or edit
    // them. Don't block save on the contents of any grandfathered escalations.
  }

  function validateAutoDismissAction(act: AutoDismissAction, next: FieldErrors): void {
    const adErr: NonNullable<FieldErrors["autoDismiss"]> = {}
    const trimmedReason = act.reason.trim()
    if (trimmedReason.length < 3) {
      adErr.reason = "Reason must be at least 3 characters"
    } else if (trimmedReason.length > 200) {
      adErr.reason = "Reason must be at most 200 characters"
    }
    const auditNote = act.audit_note ?? ""
    if (auditNote.length > 500) {
      adErr.audit_note = "Audit note must be at most 500 characters"
    }
    if (
      !Number.isFinite(act.rate_alarm_pct) ||
      act.rate_alarm_pct < 1 ||
      act.rate_alarm_pct > 100
    ) {
      adErr.rate_alarm_pct = "Rate alarm % must be between 1 and 100"
    }
    if (
      !Number.isInteger(act.rate_alarm_window_minutes) ||
      act.rate_alarm_window_minutes < 5 ||
      act.rate_alarm_window_minutes > 10080
    ) {
      adErr.rate_alarm_window_minutes = "Window must be between 5 and 10080 minutes"
    }
    if (Object.keys(adErr).length > 0) next.autoDismiss = adErr
  }

  function validateScannerCoverageAction(act: ScannerCoverageAction, next: FieldErrors): void {
    const coverageErr: NonNullable<FieldErrors["scannerCoverage"]> = {}
    if (act.type === "require_scanners") {
      if (act.required_scanners.length < 1) {
        coverageErr.required_scanners = "Select at least one scanner"
      }
    } else {
      if (
        !Number.isInteger(act.stale_after_days) ||
        act.stale_after_days < 1 ||
        act.stale_after_days > 365
      ) {
        coverageErr.stale_after_days = "Must be a whole number between 1 and 365"
      }
      // Notify-channel delivery and auto-retrigger are coming-soon legs — a
      // stale alert opens a visible violation without them — so a channel is
      // no longer required to save the rule.
    }
    if (Object.keys(coverageErr).length > 0) next.scannerCoverage = coverageErr
  }

  function validateDataRetentionAction(act: DataRetentionAction, next: FieldErrors): void {
    const floor = act.type === "delete" ? 90 : 30
    const dataRetentionErr: NonNullable<FieldErrors["dataRetention"]> = {}
    if (
      !Number.isInteger(act.after_days) ||
      act.after_days < floor ||
      act.after_days > 3650
    ) {
      dataRetentionErr.after_days = `Must be a whole number between ${floor} and 3650`
    }
    if (Object.keys(dataRetentionErr).length > 0) next.dataRetention = dataRetentionErr
  }

  function validate(): FieldErrors {
    const next: FieldErrors = {}

    const trimmedName = name.trim()
    if (trimmedName.length < 1) next.name = "Name is required"
    else if (trimmedName.length > 200) next.name = "Name must be at most 200 characters"

    if (description.length > 500) next.description = "Description must be at most 500 characters"

    if (!Number.isInteger(priority) || priority < 0) next.priority = "Priority must be a non-negative integer"

    if (category === "sla" && isSlaAction(action)) {
      validateSlaAction(action, next)
    } else if (
      category === "scanner_coverage" &&
      (isRequireScannersAction(action) || isStaleAlertAction(action))
    ) {
      validateScannerCoverageAction(action as ScannerCoverageAction, next)
    } else if (category === "auto_dismiss" && isAutoDismissAction(action)) {
      validateAutoDismissAction(action, next)
    } else if (category === "data_retention" && isDataRetentionAction(action)) {
      validateDataRetentionAction(action as DataRetentionAction, next)
    }

    return next
  }

  const validationErrors = validate()
  const hasErrors = Object.keys(validationErrors).length > 0

  async function submitWithToken(token?: string) {
    const v = validate()
    if (Object.keys(v).length > 0) {
      setErrors(v)
      return
    }
    setErrors({})

    // Typed-confirm gate: destructive `delete` data retention actions
    // require the user to type the exact confirmation phrase before we
    // submit. Archive actions skip this gate since they are recoverable.
    if (
      category === "data_retention" &&
      isDataRetentionAction(action) &&
      (action as DataRetentionAction).type === "delete"
    ) {
      const confirmed = await confirmDeleteAction()
      if (!confirmed) return
    }

    const trimmedName = name.trim()
    const trimmedDesc = description.trim()
    if (mode === "create") {
      const effectiveEnabled = category === "auto_dismiss" ? false : enabled
      await onSave({
        create: {
          category,
          name: trimmedName,
          description: trimmedDesc.length > 0 ? trimmedDesc : null,
          enabled: effectiveEnabled,
          priority,
          conditions,
          action,
        },
      })
    } else {
      const update: UpdateRulePayload = {
        name: trimmedName,
        description: trimmedDesc.length > 0 ? trimmedDesc : null,
        enabled,
        priority,
        conditions,
        action,
      }
      if (token) update.dry_run_confirmation_token = token
      await onSave({ update })
    }
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()

    if (
      category === "auto_dismiss" &&
      mode === "edit" &&
      enabled &&
      initialRule &&
      !initialRule.enabled
    ) {
      const v = validate()
      if (Object.keys(v).length > 0) {
        setErrors(v)
        return
      }
      setErrors({})
      await openDryRunDialog()
      return
    }

    await submitWithToken()
  }

  async function openDryRunDialog() {
    if (!initialRule) return
    setDryRunOpen(true)
    setDryRunLoading(true)
    setDryRunResult(null)
    setDryRunError(null)
    try {
      const res = await dryRunAndConfirm(initialRule.id)
      setDryRunResult(res)
    } catch (err) {
      setDryRunError(err instanceof Error ? err.message : "Failed to run dry-run")
    } finally {
      setDryRunLoading(false)
    }
  }

  async function handleDryRunConfirm(token: string) {
    setDryRunOpen(false)
    await submitWithToken(token)
  }

  function handleDryRunCancel() {
    setDryRunOpen(false)
    setDryRunResult(null)
    setDryRunError(null)
    setEnabled(false)
  }

  function titleFor(cat: EditableRuleCategory): string {
    if (mode === "edit") {
      if (cat === "sla") return "Edit SLA rule"
      if (cat === "scanner_coverage") return "Edit scanner coverage rule"
      if (cat === "auto_dismiss") return "Edit auto-dismiss rule"
      return "Edit data retention rule"
    }
    if (cat === "sla") return "New SLA rule"
    if (cat === "scanner_coverage") return "New scanner coverage rule"
    if (cat === "auto_dismiss") return "Create auto-dismiss rule"
    return "New data retention rule"
  }
  const title = titleFor(category)
  const submitLabel = mode === "edit" ? "Save changes" : "Create rule"
  const namePlaceholder =
    category === "sla"
      ? "e.g. Critical CVEs — 7 days"
      : category === "scanner_coverage"
        ? "e.g. Production repos require SCA + SAST"
        : category === "auto_dismiss"
          ? "e.g. Auto-dismiss test fixtures"
          : "e.g. Archive completed scans after 1 year"
  const descriptionPlaceholder =
    category === "sla"
      ? "Optional — explain when this SLA applies."
      : category === "scanner_coverage"
        ? "Optional — explain when this coverage rule applies."
        : category === "auto_dismiss"
          ? "Optional — explain when findings should be auto-dismissed."
          : "Optional — explain when this retention rule applies."
  const fieldSchema =
    category === "sla"
      ? SLA_RULE_FIELDS
      : category === "scanner_coverage"
        ? SCANNER_COVERAGE_RULE_FIELDS
        : category === "auto_dismiss"
          ? AUTO_DISMISS_RULE_FIELDS
          : DATA_RETENTION_RULE_FIELDS
  const enabledToggleLocked = mode === "create" && category === "auto_dismiss"

  return (
    <>
      {/* Backdrop */}
      <div
        className="fixed inset-0 z-40 bg-[var(--color-overlay)]"
        onClick={() => { if (!saving) onClose() }}
        aria-hidden="true"
      />

      {/* Modal */}
      <div
        role="dialog"
        aria-modal="true"
        aria-label={title}
        className="fixed left-1/2 top-1/2 z-50 flex max-h-[85vh] w-full max-w-2xl -translate-x-1/2 -translate-y-1/2 flex-col rounded-2xl border border-[var(--color-border)] bg-[var(--color-surface)] shadow-2xl"
      >
        {/* Header */}
        <div className="flex items-center justify-between border-b border-[var(--color-border)] px-6 py-4">
          <h2 className="text-sm font-semibold text-[var(--color-text-primary)]">{title}</h2>
          <button
            type="button"
            onClick={() => { if (!saving) onClose() }}
            aria-label="close"
            className="rounded p-1 text-[var(--color-text-tertiary)] hover:bg-[var(--color-surface-raised)] hover:text-[var(--color-text-primary)]"
          >
            ×
          </button>
        </div>

        {/* Tabs */}
        <div
          role="tablist"
          aria-label="Rule editor sections"
          className="flex border-b border-[var(--color-border)] bg-[var(--color-surface)] px-6"
        >
          <button
            id="tab-edit"
            role="tab"
            type="button"
            aria-selected={activeTab === "edit"}
            aria-controls="tabpanel-edit"
            onClick={() => setActiveTab("edit")}
            className={`-mb-px border-b-2 px-3 py-2.5 text-sm transition-colors ${
              activeTab === "edit"
                ? "border-[var(--color-accent)] font-semibold text-[var(--color-text-primary)]"
                : "border-transparent text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)]"
            }`}
          >
            Edit
          </button>
          <button
            id="tab-preview"
            role="tab"
            type="button"
            aria-selected={activeTab === "preview"}
            aria-controls="tabpanel-preview"
            onClick={() => {
              setActiveTab("preview")
              setPreviewRefreshKey((k) => k + 1)
            }}
            className={`-mb-px border-b-2 px-3 py-2.5 text-sm transition-colors ${
              activeTab === "preview"
                ? "border-[var(--color-accent)] font-semibold text-[var(--color-text-primary)]"
                : "border-transparent text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)]"
            }`}
          >
            Preview
          </button>
        </div>

        {/* Form */}
        <form onSubmit={handleSubmit} className="flex min-h-0 flex-1 flex-col">
          {/* Edit panel */}
          {activeTab === "edit" && (
          <div
            id="tabpanel-edit"
            role="tabpanel"
            aria-labelledby="tab-edit"
            tabIndex={0}
            className="flex-1 space-y-5 overflow-y-auto px-6 py-5"
          >
            {/* Name */}
            <FormField label="Name" htmlFor="sla-rule-name" required error={errors.name}>
              <Input
                id="sla-rule-name"
                type="text"
                required
                maxLength={200}
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder={namePlaceholder}
                invalid={!!errors.name}
              />
            </FormField>

            {/* Description */}
            <FormField label="Description" htmlFor="sla-rule-description" error={errors.description}>
              <Textarea
                id="sla-rule-description"
                rows={2}
                maxLength={500}
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                placeholder={descriptionPlaceholder}
                invalid={!!errors.description}
                className="resize-none"
              />
            </FormField>

            {/* Conditions */}
            <div>
              <label className="block text-[11px] font-semibold uppercase tracking-[0.22em] text-[var(--color-text-secondary)] mb-2">
                Conditions
              </label>
              <p className="mb-2 text-xs text-[var(--color-text-tertiary)]">
                An empty condition matches every finding (catch-all).
              </p>
              <ConditionBuilder
                value={conditions}
                onChange={setConditions}
                fields={fieldSchema}
              />
            </div>

            {/* Action */}
            <div>
              <label className="block text-[11px] font-semibold uppercase tracking-[0.22em] text-[var(--color-text-secondary)] mb-2">
                Action
              </label>
              {category === "sla" && isSlaAction(action) && (
                <SlaActionEditor
                  value={action}
                  destinations={destinations}
                  onChange={(next) => setAction(next)}
                />
              )}
              {category === "scanner_coverage" &&
                (isRequireScannersAction(action) || isStaleAlertAction(action)) && (
                  <ScannerCoverageActionEditor
                    value={action as ScannerCoverageAction}
                    onChange={(next) => setAction(next)}
                  />
                )}
              {category === "auto_dismiss" && isAutoDismissAction(action) && (
                <AutoDismissActionEditor
                  value={action}
                  onChange={(next) => setAction(next)}
                />
              )}
              {category === "data_retention" && isDataRetentionAction(action) && (
                <DataRetentionActionEditor
                  value={action as DataRetentionAction}
                  onChange={(next) => setAction(next)}
                />
              )}
              {category === "sla" && errors.deadline && (
                <p className="mt-1 text-xs text-[var(--color-severity-critical-text)]">{errors.deadline}</p>
              )}
              {category === "scanner_coverage" && errors.scannerCoverage && (
                <>
                  {errors.scannerCoverage.required_scanners && (
                    <p className="mt-1 text-xs text-[var(--color-severity-critical-text)]">
                      {errors.scannerCoverage.required_scanners}
                    </p>
                  )}
                  {errors.scannerCoverage.stale_after_days && (
                    <p className="mt-1 text-xs text-[var(--color-severity-critical-text)]">
                      {errors.scannerCoverage.stale_after_days}
                    </p>
                  )}
                </>
              )}
              {category === "auto_dismiss" && errors.autoDismiss && (
                <>
                  {errors.autoDismiss.reason && (
                    <p className="mt-1 text-xs text-[var(--color-severity-critical-text)]">
                      {errors.autoDismiss.reason}
                    </p>
                  )}
                  {errors.autoDismiss.audit_note && (
                    <p className="mt-1 text-xs text-[var(--color-severity-critical-text)]">
                      {errors.autoDismiss.audit_note}
                    </p>
                  )}
                  {errors.autoDismiss.rate_alarm_pct && (
                    <p className="mt-1 text-xs text-[var(--color-severity-critical-text)]">
                      {errors.autoDismiss.rate_alarm_pct}
                    </p>
                  )}
                  {errors.autoDismiss.rate_alarm_window_minutes && (
                    <p className="mt-1 text-xs text-[var(--color-severity-critical-text)]">
                      {errors.autoDismiss.rate_alarm_window_minutes}
                    </p>
                  )}
                </>
              )}
              {category === "data_retention" && errors.dataRetention?.after_days && (
                <p className="mt-1 text-xs text-[var(--color-severity-critical-text)]">
                  {errors.dataRetention.after_days}
                </p>
              )}
            </div>

            {/* Priority + Enabled */}
            <div className="flex items-end gap-4">
              <FormField
                label="Priority"
                htmlFor="sla-rule-priority"
                hint={errors.priority ? undefined : "Lower = higher priority. First match wins."}
                error={errors.priority}
                className="flex-1"
              >
                <Input
                  id="sla-rule-priority"
                  type="number"
                  min={0}
                  value={priority}
                  onChange={(e) => setPriority(Math.max(0, Number(e.target.value)))}
                  invalid={!!errors.priority}
                />
              </FormField>

              <div className="pb-5">
                <label
                  className={`flex select-none items-center gap-2 ${
                    enabledToggleLocked ? "cursor-not-allowed" : "cursor-pointer"
                  }`}
                >
                  <input
                    type="checkbox"
                    checked={enabledToggleLocked ? false : enabled}
                    disabled={enabledToggleLocked}
                    onChange={(e) => setEnabled(e.target.checked)}
                    className="h-4 w-4 rounded border-[var(--color-border)] accent-[var(--color-accent)] disabled:opacity-60"
                  />
                  <span className="text-sm text-[var(--color-text-primary)]">Enabled</span>
                </label>
                {enabledToggleLocked && (
                  <p className="mt-1 max-w-[18rem] text-2xs text-[var(--color-text-tertiary)]">
                    Auto-dismiss rules must be created disabled. Enable after a
                    dry-run confirmation.
                  </p>
                )}
              </div>
            </div>

          </div>
          )}

          {/* Preview panel */}
          {activeTab === "preview" && (
          <div
            id="tabpanel-preview"
            role="tabpanel"
            aria-labelledby="tab-preview"
            tabIndex={0}
            className="flex-1 overflow-y-auto px-6 py-5"
          >
            <RulePreview
              ruleId={initialRule?.id ?? null}
              refreshKey={previewRefreshKey}
            />
          </div>
          )}

          {/* Footer */}
          <div className="flex flex-col gap-3 border-t border-[var(--color-border)] px-6 py-4">
            {saveError && (
              <p className="text-sm text-[var(--color-severity-critical-text)]">{saveError}</p>
            )}
            <div className="flex justify-end gap-3">
              <Button variant="secondary" size="md" onClick={() => { if (!saving) onClose() }}>
                Cancel
              </Button>
              <Button type="submit" variant="primary" size="md" disabled={saving || hasErrors} isLoading={saving}>
                {saving ? "Saving…" : submitLabel}
              </Button>
            </div>
          </div>
        </form>
      </div>

      <DryRunConfirmDialog
        open={dryRunOpen}
        ruleName={name.trim()}
        result={dryRunResult}
        loading={dryRunLoading}
        error={dryRunError}
        onConfirm={(token) => { void handleDryRunConfirm(token) }}
        onCancel={handleDryRunCancel}
      />

      {/* Typed-confirm dialog for destructive delete actions */}
      {deleteConfirmState.open && (
        <>
          <div
            className="fixed inset-0 z-[60] bg-[var(--color-overlay)]"
            onClick={() => resolveDeleteConfirm(false)}
            aria-hidden="true"
          />
          <div
            role="dialog"
            aria-modal="true"
            aria-label="Confirm delete action"
            className="fixed left-1/2 top-1/2 z-[70] flex w-full max-w-md -translate-x-1/2 -translate-y-1/2 flex-col rounded-2xl border border-[var(--color-severity-critical)] bg-[var(--color-surface)] shadow-2xl"
          >
            <div className="border-b border-[var(--color-severity-critical)] bg-[var(--color-severity-critical)]/10 px-6 py-4">
              <h2 className="text-sm font-semibold text-[var(--color-severity-critical-text)]">
                Confirm delete action
              </h2>
            </div>
            <div className="space-y-4 px-6 py-5">
              <p className="text-sm text-[var(--color-text-primary)]">
                This rule will permanently delete scan results after the
                configured period. Type{" "}
                <span className="font-mono font-semibold text-[var(--color-severity-critical-text)]">
                  delete data retention
                </span>{" "}
                to confirm.
              </p>
              <Input
                type="text"
                value={deleteConfirmInput}
                onChange={(e) => setDeleteConfirmInput(e.target.value)}
                placeholder="delete data retention"
                autoFocus
                aria-label="Delete confirmation phrase"
              />
            </div>
            <div className="flex justify-end gap-3 border-t border-[var(--color-border)] px-6 py-4">
              <Button variant="secondary" size="md" onClick={() => resolveDeleteConfirm(false)}>
                Cancel
              </Button>
              <Button
                variant="destructive"
                size="md"
                disabled={deleteConfirmInput !== "delete data retention"}
                onClick={() => resolveDeleteConfirm(true)}
              >
                Confirm
              </Button>
            </div>
          </div>
        </>
      )}
    </>
  )
}
