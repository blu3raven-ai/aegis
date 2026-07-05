"use client"

import { Sheet } from "@/components/ui/Sheet"

/**
 * Thin wrapper around the Sheet primitive so the existing Account modals
 * (Email/Username/Password/TOTP) share the right-side drawer chrome without
 * each having to know about Sheet directly. New surfaces should prefer
 * importing Sheet directly.
 */
export function Modal({
  open,
  title,
  onClose,
  children,
}: {
  open: boolean
  title: string
  onClose: () => void
  children: React.ReactNode
}) {
  return (
    <Sheet open={open} onClose={onClose} title={title} size="sm">
      {children}
    </Sheet>
  )
}
