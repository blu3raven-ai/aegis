"use client"

import { useEffect, useState, useCallback } from "react"
import { usePathname } from "next/navigation"
import { useMobileSidebar } from "@/components/layout/MobileSidebarContext"
import { SidebarContent } from "@/components/layout/SidebarContent"
import type { SidebarContentProps } from "@/components/layout/SidebarContent"

export interface MobileSidebarProps extends SidebarContentProps {}

export function MobileSidebar(props: MobileSidebarProps) {
  const { open, setOpen } = useMobileSidebar()
  const pathname = usePathname()

  // Track whether the DOM nodes should be mounted (stays true while transitioning out)
  const [mounted, setMounted] = useState(false)
  // Track whether the visible transition has activated (controls opacity/transform)
  const [visible, setVisible] = useState(false)

  // Close on route change
  useEffect(() => {
    setOpen(false)
  }, [pathname, setOpen])

  // Sync mount/visible states with open prop
  useEffect(() => {
    if (open) {
      setMounted(true)
      // Double-raf to ensure the DOM has painted before adding the visible class
      requestAnimationFrame(() => {
        requestAnimationFrame(() => {
          setVisible(true)
        })
      })
    } else {
      setVisible(false)
    }
  }, [open])

  // Unmount after the exit transition finishes
  const handleTransitionEnd = useCallback(() => {
    if (!visible) {
      setMounted(false)
    }
  }, [visible])

  // Prevent body scroll when open
  useEffect(() => {
    if (open) {
      document.body.style.overflow = "hidden"
    } else {
      document.body.style.overflow = ""
    }
    return () => {
      document.body.style.overflow = ""
    }
  }, [open])

  if (!mounted) return null

  return (
    <>
      {/* Backdrop overlay */}
      <div
        className={`fixed inset-0 z-40 bg-[var(--color-overlay-strong)] transition-opacity duration-200 ${
          visible ? "opacity-100" : "opacity-0"
        }`}
        onClick={() => setOpen(false)}
        aria-hidden
      />

      {/* Drawer */}
      <nav
        onTransitionEnd={handleTransitionEnd}
        className={`fixed inset-y-0 left-0 z-50 w-72 flex flex-col bg-[var(--color-surface)] border-r border-[var(--color-border)] shadow-xl transition-transform duration-200 ease-in-out ${
          visible ? "translate-x-0" : "-translate-x-full"
        }`}
      >
        <SidebarContent
          {...props}
          collapsed={false}
          onNavigate={() => setOpen(false)}
        />
      </nav>
    </>
  )
}
