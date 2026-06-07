"use client"

/**
 * Gate dialog shown when an admin attempts to enable an auto-dismiss
 * rule. Surfaces the dry-run impact (match count + a sample of
 * findings that would be dismissed) and forces a typed confirmation
 * of the rule's name before the rule can be activated.
 *
 * The dialog never persists the confirmation token outside its own
 * lifetime — it is handed back via onConfirm so the parent can include
 * it in the immediate update call. ESC closes (when allowed) and the
 * Enable button is gated on an exact, case-sensitive, trimmed match
 * of the rule name.
 */

import { useEffect, useMemo, useRef, useState } from "react"
import type { DryRunConfirmation } from "@/lib/client/rules-api"

interface DryRunConfirmDialogProps {
  open: boolean
  ruleName: string
  result: DryRunConfirmation | null
  loading: boolean
  error?: string | null
  onConfirm: (token: string) => void
  onCancel: () => void
}

function formatExpiresIn(validUntilIso: string): string {
  const expires = new Date(validUntilIso).getTime()
  if (Number.isNaN(expires)) return ""
  const diffMs = expires - Date.now()
  if (diffMs <= 0) return "Token expired"
  const minutes = Math.round(diffMs / 60_000)
  if (minutes < 1) return "Token expires in <1 min"
  if (minutes < 60) return `Token expires in ${minutes} min`
  const hours = Math.floor(minutes / 60)
  const remMinutes = minutes % 60
  return remMinutes === 0
    ? `Token expires in ${hours} h`
    : `Token expires in ${hours} h ${remMinutes} min`
}

function severityClasses(severity: string): string {
  switch (severity.toLowerCase()) {
    case "critical":
      return "text-[var(--color-severity-critical)]"
    case "high":
      return "text-[var(--color-severity-high)]"
    case "medium":
      return "text-[var(--color-severity-medium)]"
    case "low":
      return "text-[var(--color-severity-low)]"
    default:
      return "text-[var(--color-text-secondary)]"
  }
}

export function DryRunConfirmDialog({
  open,
  ruleName,
  result,
  loading,
  error,
  onConfirm,
  onCancel,
}: DryRunConfirmDialogProps) {
  const [typed, setTyped] = useState("")
  const dialogRef = useRef<HTMLDivElement>(null)
  const inputRef = useRef<HTMLInputElement>(null)

  useEffect(() => {
    if (!open) {
      setTyped("")
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
    const focusTarget = inputRef.current ?? dialogRef.current
    focusTarget?.focus()
  }, [open, result])

  const trimmedTyped = typed.trim()
  const nameMatches = useMemo(
    () => trimmedTyped === ruleName && ruleName.length > 0,
    [trimmedTyped, ruleName],
  )

  const enableDisabled = !nameMatches || loading || result === null

  if (!open) return null

  const title = "Enable auto-dismiss rule"
  const matchCount = result?.match_count ?? 0
  const samples = result?.sample_matches ?? []

  return (
    <>
      <div
        className="fixed inset-0 z-[60] bg-[var(--color-overlay-strong)]"
        onClick={() => { if (!loading) onCancel() }}
        aria-hidden="true"
      />

      <div
        ref={dialogRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby="dry-run-confirm-title"
        tabIndex={-1}
        className="fixed left-1/2 top-1/2 z-[61] flex max-h-[85vh] w-full max-w-2xl -translate-x-1/2 -translate-y-1/2 flex-col rounded-2xl border border-[var(--color-border)] bg-[var(--color-surface)] shadow-2xl focus:outline-none"
      >
        <div className="border-b border-[var(--color-border)] px-6 py-4">
          <h2
            id="dry-run-confirm-title"
            className="text-lg font-semibold tracking-tight text-[var(--color-text-primary)]"
          >
            {title}
          </h2>
          <p className="mt-1 truncate text-xs text-[var(--color-text-secondary)]">
            {ruleName}
          </p>
        </div>

        <div className="flex-1 space-y-5 overflow-y-auto px-6 py-5">
          {loading && result === null && (
            <div className="flex items-center gap-3 rounded-lg border border-[var(--color-border)] bg-[var(--color-surface-raised)] px-4 py-3">
              <span
                aria-hidden="true"
                className="inline-block h-4 w-4 animate-spin rounded-full border-2 border-[var(--color-text-tertiary)] border-t-[var(--color-accent)]"
              />
              <p className="text-sm text-[var(--color-text-secondary)]">
                Running dry-run against the last 1000 findings…
              </p>
            </div>
          )}

          {result !== null && (
            <div className="rounded-lg border border-[var(--color-border)] bg-[var(--color-surface-raised)] px-4 py-3">
              {matchCount === 0 ? (
                <p className="text-sm text-[var(--color-text-primary)]">
                  This rule wouldn&apos;t dismiss anything against the most
                  recent findings. You can still enable it — it will dismiss
                  matches as they arrive.
                </p>
              ) : (
                <p className="text-sm text-[var(--color-text-primary)]">
                  <span className="font-semibold">{matchCount} findings</span>{" "}
                  would be auto-dismissed once this rule is enabled.
                </p>
              )}
              <p className="mt-1 text-2xs uppercase tracking-[0.14em] text-[var(--color-text-tertiary)]">
                {formatExpiresIn(result.valid_until)}
              </p>
            </div>
          )}

          {result !== null && samples.length > 0 && (
            <div>
              <h3 className="mb-2 text-base font-semibold text-[var(--color-text-primary)]">
                Sample matches ({samples.length})
              </h3>
              <div className="overflow-hidden rounded-lg border border-[var(--color-border)]">
                <table className="w-full border-collapse text-sm">
                  <thead className="bg-[var(--color-surface-raised)]">
                    <tr>
                      <th className="px-3 py-2 text-left text-2xs font-semibold uppercase tracking-[0.14em] text-[var(--color-text-secondary)]">
                        Severity
                      </th>
                      <th className="px-3 py-2 text-left text-2xs font-semibold uppercase tracking-[0.14em] text-[var(--color-text-secondary)]">
                        Scanner
                      </th>
                      <th className="px-3 py-2 text-left text-2xs font-semibold uppercase tracking-[0.14em] text-[var(--color-text-secondary)]">
                        Repo
                      </th>
                      <th className="px-3 py-2 text-left text-2xs font-semibold uppercase tracking-[0.14em] text-[var(--color-text-secondary)]">
                        File
                      </th>
                      <th className="px-3 py-2 text-left text-2xs font-semibold uppercase tracking-[0.14em] text-[var(--color-text-secondary)]">
                        CVE
                      </th>
                    </tr>
                  </thead>
                  <tbody>
                    {samples.map((m) => (
                      <tr
                        key={m.finding_id}
                        className="border-t border-[var(--color-border)]"
                      >
                        <td className={`px-3 py-2 text-sm font-medium ${severityClasses(m.severity)}`}>
                          {m.severity}
                        </td>
                        <td className="px-3 py-2 text-sm text-[var(--color-text-primary)]">
                          {m.scanner}
                        </td>
                        <td className="px-3 py-2 text-sm text-[var(--color-text-primary)]">
                          {m.repo_id}
                        </td>
                        <td
                          className="max-w-[16rem] truncate px-3 py-2 text-sm text-[var(--color-text-secondary)]"
                          title={m.file_path ?? ""}
                        >
                          {m.file_path ?? "—"}
                        </td>
                        <td className="px-3 py-2 text-sm text-[var(--color-text-secondary)]">
                          {m.cve_id ?? "—"}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          <div>
            <label
              htmlFor="dry-run-typed-confirm"
              className="mb-1 block text-[11px] font-semibold uppercase tracking-[0.22em] text-[var(--color-text-secondary)]"
            >
              Type the rule name to confirm
            </label>
            <input
              id="dry-run-typed-confirm"
              ref={inputRef}
              type="text"
              autoComplete="off"
              spellCheck={false}
              value={typed}
              onChange={(e) => setTyped(e.target.value)}
              placeholder={ruleName}
              disabled={loading}
              className="w-full rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-input)] px-3 py-2 text-sm text-[var(--color-text-primary)] placeholder:text-[var(--color-text-tertiary)] focus:border-[var(--color-severity-critical)] focus:outline-none focus:ring-1 focus:ring-[var(--color-severity-critical)] disabled:opacity-60"
            />
            <p className="mt-1 text-xs text-[var(--color-severity-critical)]">
              Type <span className="font-mono">{ruleName}</span> to enable. This
              will start auto-dismissing matching findings immediately.
            </p>
          </div>

          {error && (
            <div
              role="alert"
              className="rounded-lg border border-[var(--color-severity-critical)] bg-[var(--color-surface-raised)] px-3 py-2 text-sm text-[var(--color-severity-critical)]"
            >
              {error}
            </div>
          )}
        </div>

        <div className="flex justify-end gap-3 border-t border-[var(--color-border)] px-6 py-4">
          <button
            type="button"
            onClick={onCancel}
            className="rounded-lg border border-[var(--color-border)] px-4 py-2 text-sm font-medium text-[var(--color-text-secondary)] hover:bg-[var(--color-surface-raised)]"
          >
            Cancel
          </button>
          <button
            type="button"
            disabled={enableDisabled}
            onClick={() => {
              if (result !== null) onConfirm(result.token)
            }}
            className="rounded-lg bg-[var(--color-severity-critical)] px-4 py-2 text-sm font-semibold text-[var(--color-on-danger)] hover:opacity-90 disabled:opacity-50"
          >
            Enable rule
          </button>
        </div>
      </div>
    </>
  )
}
