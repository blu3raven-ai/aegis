"use client"

import { useCallback, useEffect, useRef, useState } from "react"
import { createPortal } from "react-dom"
import { Button } from "@/components/ui/Button"


interface ExternalLinkConfirmProps {
  url: string | null
  onClose: () => void
}

export function ExternalLinkConfirm({ url, onClose }: ExternalLinkConfirmProps) {
  const cancelRef = useRef<HTMLButtonElement>(null)

  useEffect(() => {
    if (!url) return
    cancelRef.current?.focus()
    function handleKey(e: KeyboardEvent) {
      if (e.key === "Escape") onClose()
    }
    document.addEventListener("keydown", handleKey)
    return () => document.removeEventListener("keydown", handleKey)
  }, [url, onClose])

  if (!url) return null

  return createPortal(
    <div className="fixed inset-0 z-[9999] flex items-center justify-center" role="dialog" aria-modal="true" aria-labelledby="ext-link-title">
      {/* Backdrop */}
      <div className="absolute inset-0 bg-[var(--color-overlay-strong)]" onClick={onClose} />

      {/* Dialog */}
      <div className="relative mx-4 w-full max-w-md rounded-2xl border border-[var(--color-border)] bg-[var(--color-surface)] p-6 shadow-2xl">
        {/* Icon + Title */}
        <div className="flex items-start gap-3">
          <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl bg-[var(--color-state-pending-subtle)]">
            <svg className="h-5 w-5 text-[var(--color-state-pending)]" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.5} strokeLinecap="round" strokeLinejoin="round">
              <path d="M13.5 6H5.25A2.25 2.25 0 0 0 3 8.25v10.5A2.25 2.25 0 0 0 5.25 21h10.5A2.25 2.25 0 0 0 18 18.75V10.5m-10.5 6L21 3m0 0h-5.25M21 3v5.25" />
            </svg>
          </div>
          <div>
            <h3 id="ext-link-title" className="text-sm font-semibold text-[var(--color-text-primary)]">
              Leaving Aegis
            </h3>
            <p className="mt-1 text-xs text-[var(--color-text-secondary)]">
              You are about to visit an external site.
            </p>
          </div>
        </div>

        {/* URL preview */}
        <div className="mt-4 rounded-xl border border-[var(--color-border)] bg-[var(--color-surface-raised)] px-3 py-2.5">
          <p className="break-all font-[family-name:var(--font-jetbrains-mono)] text-xs text-[var(--color-text-secondary)]">
            {url}
          </p>
        </div>

        {/* Warning */}
        <p className="mt-3 text-xs leading-relaxed text-[var(--color-text-secondary)]">
          This link is from a security advisory and has not been verified by Aegis.
        </p>

        {/* Actions */}
        <div className="mt-5 flex items-center justify-end gap-3">
          <Button
            ref={cancelRef}
            variant="secondary"
            size="md"
            onClick={onClose}
          >
            Cancel
          </Button>
          <a
            href={url}
            target="_blank"
            rel="noreferrer noopener"
            onClick={onClose}
            className="inline-flex items-center gap-1.5 rounded-lg bg-[var(--color-accent)] px-4 py-2 text-sm font-medium text-[var(--color-accent-on)] hover:bg-[var(--color-accent-hover)] focus:outline-none focus:ring-2 focus:ring-[var(--color-accent)]"
          >
            Continue
            <svg className="h-3.5 w-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round">
              <path d="M13.5 6H5.25A2.25 2.25 0 0 0 3 8.25v10.5A2.25 2.25 0 0 0 5.25 21h10.5A2.25 2.25 0 0 0 18 18.75V10.5m-10.5 6L21 3m0 0h-5.25M21 3v5.25" />
            </svg>
          </a>
        </div>
      </div>
    </div>,
    document.body
  )
}

/** Hook to manage external link confirmation state */
export function useExternalLinkConfirm() {
  const [pendingUrl, setPendingUrl] = useState<string | null>(null)

  const requestNavigation = useCallback((url: string) => {
    setPendingUrl(url)
  }, [])

  const close = useCallback(() => {
    setPendingUrl(null)
  }, [])

  return { pendingUrl, requestNavigation, close }
}
