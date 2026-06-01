"use client"

import { useEffect, useRef } from "react"

interface DialogProps {
  open: boolean
  onClose: () => void
  onConfirm?: () => void
  title: string
  description?: string
  children?: React.ReactNode
  confirmLabel?: string
  cancelLabel?: string
  variant?: "danger" | "info"
}

export function Dialog({
  open,
  onClose,
  onConfirm,
  title,
  description,
  children,
  confirmLabel = "OK",
  cancelLabel = "Cancel",
  variant = "info",
}: DialogProps) {
  const dialogRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (!open) return

    function handleKeyDown(e: KeyboardEvent) {
      if (e.key === "Escape") onClose()
    }

    window.addEventListener("keydown", handleKeyDown)
    return () => window.removeEventListener("keydown", handleKeyDown)
  }, [open, onClose])

  if (!open) return null

  return (
    <div className="fixed inset-0 z-[100] flex items-center justify-center p-4">
      {/* Backdrop */}
      <div
        className="fixed inset-0 bg-[var(--color-overlay-strong)] transition-opacity"
        onClick={onClose}
        aria-hidden="true"
      />

      {/* Dialog */}
      <div 
        ref={dialogRef}
        className="relative w-full max-w-md transform overflow-hidden rounded-2xl bg-[var(--color-surface)] p-6 text-left align-middle shadow-xl transition-all border border-[var(--color-border)]"
        role="dialog"
        aria-modal="true"
        aria-labelledby="dialog-title"
      >
        <h3 
          id="dialog-title"
          className="text-lg font-bold leading-6 text-[var(--color-text-primary)]"
        >
          {title}
        </h3>
        {description && (
          <div className="mt-2">
            <p className="text-sm text-[var(--color-text-secondary)] leading-relaxed">
              {description}
            </p>
          </div>
        )}

        {children && (
          <div className="mt-4">
            {children}
          </div>
        )}

        {/* Action buttons are only shown if not providing custom children, 
            OR if explicitly requested. For forms, we usually want the 
            buttons inside the children block. */}
        {!children && (
          <div className="mt-6 flex justify-end gap-3">
            {onConfirm && (
              <button
                type="button"
                className="rounded-lg px-4 py-2 text-sm font-semibold text-[var(--color-text-secondary)] hover:bg-[var(--color-surface-raised)] transition-colors"
                onClick={onClose}
              >
                {cancelLabel}
              </button>
            )}
            <button
              type="button"
              autoFocus
              className={`rounded-lg px-4 py-2 text-sm font-semibold text-[var(--color-on-danger)] transition-colors ${
                variant === "danger"
                  ? "bg-[var(--color-severity-critical)] hover:opacity-90"
                  : "bg-[var(--color-accent)] hover:bg-[var(--color-accent-hover)]"
              }`}
              onClick={() => {
                if (onConfirm) {
                  onConfirm()
                } else {
                  onClose()
                }
              }}
            >
              {confirmLabel}
            </button>
          </div>
        )}
      </div>
    </div>
  )
}
