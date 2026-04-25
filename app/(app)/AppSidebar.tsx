"use client"

import { useState, useEffect } from "react"
import { SidebarContent } from "@/components/layout/SidebarContent"
import type { SidebarContentProps } from "@/components/layout/SidebarContent"

type OmitCollapsed<T> = Omit<T, "collapsed">
export interface AppSidebarProps extends OmitCollapsed<SidebarContentProps> {
  open: boolean
  setSearchOpen: (open: boolean) => void
}

export function AppSidebar({ open, setSearchOpen, ...props }: AppSidebarProps) {
  const [collapsed, setCollapsed] = useState(false)
  const [mounted, setMounted] = useState(false)

  useEffect(() => {
    setMounted(true)
    const stored = localStorage.getItem("sidebar-collapsed")
    if (stored !== null) setCollapsed(stored === "true")
  }, [])

  // Listen for custom "sidebar-collapse" events dispatched by other components
  // (e.g. settings layout auto-collapse) — same-tab signalling that localStorage
  // alone cannot provide (the storage event only fires in other tabs).
  useEffect(() => {
    function handleCollapse() {
      setCollapsed(true)
    }
    window.addEventListener("sidebar-collapse", handleCollapse)
    return () => window.removeEventListener("sidebar-collapse", handleCollapse)
  }, [])

  const toggle = () => {
    setCollapsed((prev) => {
      const next = !prev
      localStorage.setItem("sidebar-collapsed", String(next))
      return next
    })
  }

  const width = !mounted || !collapsed ? "w-56" : "w-14"

  return (
    <nav
      className={`hidden md:flex relative shrink-0 flex-col bg-[var(--color-surface)] border-r border-[var(--color-border)] transition-[width] duration-200 ease-in-out ${width}`}
    >
      <SidebarContent
        {...props}
        collapsed={collapsed}
        searchOpen={open}
        onSearchOpen={setSearchOpen}
      />
    </nav>
  )
}
