"use client"

import { useRef } from "react"
import { Button } from "@/components/ui/Button"
import { useDialogA11y } from "@/lib/client/use-dialog-a11y"

type DialogSize = "sm" | "md" | "lg" | "xl"

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
  /** Panel width. Defaults to "sm" (max-w-md) — the legacy confirm-dialog size. */
  size?: DialogSize
  /** Sticky, non-scrolling footer (e.g. Save / Cancel) pinned below the body. */
  footer?: React.ReactNode
}

// Mirrors components/ui/Sheet.tsx so Dialog and Sheet share one width scale.
const sizeClasses: Record<DialogSize, string> = {
  sm: "max-w-md",
  md: "max-w-lg",
  lg: "max-w-2xl",
  xl: "max-w-4xl",
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
  size = "sm",
  footer,
}: DialogProps) {
  const dialogRef = useRef<HTMLDivElement>(null)
  useDialogA11y(dialogRef, onClose, open)

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
        tabIndex={-1}
        className={`relative flex max-h-[85vh] w-full ${sizeClasses[size]} transform flex-col overflow-hidden rounded-2xl bg-[var(--color-surface)] text-left align-middle shadow-xl transition-all border border-[var(--color-border)] focus:outline-none`}
        role="dialog"
        aria-modal="true"
        aria-labelledby="dialog-title"
      >
        {/* Scrollable body — tall settings forms scroll here while the footer stays pinned. */}
        <div className="flex-1 overflow-y-auto p-6">
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

          {/* Default action buttons are only shown when there are no custom
              children and no footer — i.e. the legacy confirm-dialog shape.
              For forms, the buttons live in `footer` or inside `children`. */}
          {!children && !footer && (
            <div className="mt-6 flex justify-end gap-3">
              {onConfirm && (
                <Button
                  variant="ghost"
                  size="md"
                  onClick={onClose}
                >
                  {cancelLabel}
                </Button>
              )}
              <Button
                variant={variant === "danger" ? "destructive" : "primary"}
                size="md"
                autoFocus
                onClick={() => {
                  if (onConfirm) {
                    onConfirm()
                  } else {
                    onClose()
                  }
                }}
              >
                {confirmLabel}
              </Button>
            </div>
          )}
        </div>

        {footer && (
          <div className="border-t border-[var(--color-border)] px-6 py-4">
            {footer}
          </div>
        )}
      </div>
    </div>
  )
}
