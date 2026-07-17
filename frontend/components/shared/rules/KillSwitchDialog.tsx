"use client"

import { useEffect, useMemo, useRef, useState } from "react"
import type { RuleCategory } from "@/lib/client/rules-api"
import { Button } from "@/components/ui/Button"
import { FormField } from "@/components/ui/FormField"
import { Input } from "@/components/ui/Input"
import { Textarea } from "@/components/ui/Textarea"

interface KillSwitchDialogProps {
  open: boolean
  category: RuleCategory
  loading: boolean
  error?: string | null
  onConfirm: (reason: string) => void
  onCancel: () => void
}

const CONFIRM_PHRASES: Partial<Record<RuleCategory, string>> = {
  auto_dismiss: "kill auto-dismiss",
}

const TITLES: Partial<Record<RuleCategory, string>> = {
  auto_dismiss: "Kill auto-dismiss",
}

const BODIES: Partial<Record<RuleCategory, string>> = {
  auto_dismiss:
    "This immediately stops all auto-dismiss rules from acting on incoming findings for this org. Rules remain configured but inert until the kill switch is removed.",
}

const REASON_MAX = 500

export function KillSwitchDialog({
  open,
  category,
  loading,
  error,
  onConfirm,
  onCancel,
}: KillSwitchDialogProps) {
  const [typed, setTyped] = useState("")
  const [reason, setReason] = useState("")
  const dialogRef = useRef<HTMLDivElement>(null)
  const reasonRef = useRef<HTMLTextAreaElement>(null)

  useEffect(() => {
    if (!open) {
      setTyped("")
      setReason("")
    }
  }, [open])

  useEffect(() => {
    if (!open) return
    function onKeyDown(e: KeyboardEvent) {
      if (e.key === "Escape" && !loading) onCancel()
    }
    window.addEventListener("keydown", onKeyDown)
    return () => window.removeEventListener("keydown", onKeyDown)
  }, [open, loading, onCancel])

  useEffect(() => {
    if (!open) return
    const target = reasonRef.current ?? dialogRef.current
    target?.focus()
  }, [open])

  const requiredPhrase = CONFIRM_PHRASES[category] ?? ""
  const title = TITLES[category] ?? "Kill switch"
  const body = BODIES[category] ?? ""

  const phraseMatches = useMemo(
    () => typed.trim() === requiredPhrase && requiredPhrase.length > 0,
    [typed, requiredPhrase],
  )

  const confirmDisabled = !phraseMatches || loading

  if (!open) return null

  return (
    <>
      <div
        className="fixed inset-0 z-[60] bg-[var(--color-overlay-strong)]"
        onClick={() => {
          if (!loading) onCancel()
        }}
        aria-hidden="true"
      />

      <div
        ref={dialogRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby="kill-switch-title"
        tabIndex={-1}
        className="fixed left-1/2 top-1/2 z-[61] flex max-h-[85vh] w-full max-w-lg -translate-x-1/2 -translate-y-1/2 flex-col rounded-2xl border border-[var(--color-border)] bg-[var(--color-surface)] shadow-2xl focus:outline-none"
      >
        <div className="border-b border-[var(--color-border)] px-6 py-4">
          <h2
            id="kill-switch-title"
            className="text-lg font-semibold tracking-tight text-[var(--color-text-primary)]"
          >
            {title}
          </h2>
        </div>

        <div className="flex-1 space-y-5 overflow-y-auto px-6 py-5">
          <p className="text-sm text-[var(--color-text-primary)]">{body}</p>

          <FormField
            label="Why are you killing auto-dismiss? (optional)"
            htmlFor="kill-switch-reason"
            labelSuffix={`${reason.length}/${REASON_MAX}`}
          >
            <Textarea
              id="kill-switch-reason"
              ref={reasonRef}
              value={reason}
              onChange={(e) => setReason(e.target.value.slice(0, REASON_MAX))}
              disabled={loading}
              rows={3}
              maxLength={REASON_MAX}
              placeholder="Incident response, suspected misconfiguration, etc."
            />
          </FormField>

          <FormField
            label="Type to confirm"
            htmlFor="kill-switch-confirm"
            error={
              <>
                Type <span className="font-mono">{requiredPhrase}</span> to engage
                the kill switch. All auto-dismiss rules will stop acting on new
                findings.
              </>
            }
          >
            <Input
              id="kill-switch-confirm"
              type="text"
              autoComplete="off"
              spellCheck={false}
              value={typed}
              onChange={(e) => setTyped(e.target.value)}
              placeholder={requiredPhrase}
              disabled={loading}
              invalid
            />
          </FormField>

          {error && (
            <div
              role="alert"
              className="rounded-md border border-[var(--color-severity-critical)] bg-[var(--color-surface-raised)] px-3 py-2 text-sm text-[var(--color-severity-critical-text)]"
            >
              {error}
            </div>
          )}
        </div>

        <div className="flex justify-end gap-3 border-t border-[var(--color-border)] px-6 py-4">
          <Button
            variant="secondary"
            size="md"
            onClick={onCancel}
            disabled={loading}
          >
            Cancel
          </Button>
          <Button
            variant="destructive"
            size="md"
            disabled={confirmDisabled}
            isLoading={loading}
            onClick={() => onConfirm(reason.trim())}
          >
            {loading ? "Killing…" : "Kill auto-dismiss"}
          </Button>
        </div>
      </div>
    </>
  )
}
