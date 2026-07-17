"use client"

import { useEffect, useRef, useState } from "react"
import type { SbomFormat } from "@/lib/client/sbom-api"
import { Button } from "@/components/ui/Button"
import { handleRovingKeyDown } from "@/components/ui/roving"

const FORMAT_LABELS: Record<SbomFormat, string> = {
  "cyclonedx-json": "CycloneDX JSON",
  "cyclonedx-xml": "CycloneDX XML",
  "spdx-json": "SPDX JSON",
  "spdx-tag-value": "SPDX Tag-Value",
}

const FORMAT_EXT: Record<SbomFormat, string> = {
  "cyclonedx-json": "cyclonedx.json",
  "cyclonedx-xml": "cyclonedx.xml",
  "spdx-json": "spdx.json",
  "spdx-tag-value": "spdx.tv",
}

const FORMATS = Object.keys(FORMAT_LABELS) as SbomFormat[]

export function SbomExportMenu({
  repoName,
  onExport,
  loading = false,
}: {
  repoName: string
  onExport: (format: SbomFormat, filename: string) => void
  loading?: boolean
}) {
  const [open, setOpen] = useState(false)
  // Roving-tabindex active item; -1 while the menu is closed.
  const [activeIndex, setActiveIndex] = useState(-1)
  const ref = useRef<HTMLDivElement>(null)
  const triggerRef = useRef<HTMLButtonElement>(null)
  const itemRefs = useRef<Array<HTMLButtonElement | null>>([])

  useEffect(() => {
    function handleClick(e: MouseEvent) {
      if (ref.current && !ref.current.contains(e.target as Node)) {
        setOpen(false)
        setActiveIndex(-1)
      }
    }
    document.addEventListener("mousedown", handleClick)
    return () => document.removeEventListener("mousedown", handleClick)
  }, [])

  // Drive focus from activeIndex so arrow keys move the real focus ring (and a
  // screen reader follows), keeping the menu a single tab stop.
  useEffect(() => {
    if (open && activeIndex >= 0) itemRefs.current[activeIndex]?.focus()
  }, [open, activeIndex])

  function openMenu(index: number) {
    setOpen(true)
    setActiveIndex(index)
  }

  function closeMenu(restoreFocus: boolean) {
    setOpen(false)
    setActiveIndex(-1)
    if (restoreFocus) triggerRef.current?.focus()
  }

  function handleSelect(fmt: SbomFormat) {
    closeMenu(true)
    const safeName = repoName.replace(/[^a-z0-9_.-]/gi, "-").toLowerCase()
    onExport(fmt, `${safeName}.${FORMAT_EXT[fmt]}`)
  }

  function handleTriggerKeyDown(e: React.KeyboardEvent) {
    if (e.key === "ArrowDown") {
      e.preventDefault()
      openMenu(0)
    } else if (e.key === "ArrowUp") {
      e.preventDefault()
      openMenu(FORMATS.length - 1)
    }
  }

  function handleMenuKeyDown(e: React.KeyboardEvent) {
    if (e.key === "Escape") {
      e.preventDefault()
      closeMenu(true)
      return
    }
    if (e.key === "Tab") {
      // Let focus leave naturally; just dismiss the menu.
      closeMenu(false)
      return
    }
    handleRovingKeyDown(e, {
      index: activeIndex,
      count: FORMATS.length,
      orientation: "vertical",
      onMove: setActiveIndex,
    })
  }

  return (
    <div ref={ref} className="relative">
      <Button
        ref={triggerRef}
        variant="secondary"
        size="sm"
        disabled={loading}
        isLoading={loading}
        onClick={() => (open ? closeMenu(false) : openMenu(0))}
        onKeyDown={handleTriggerKeyDown}
        aria-haspopup="true"
        aria-expanded={open}
        leadingIcon={
          !loading ? (
            <svg
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth={1.5}
              strokeLinecap="round"
              strokeLinejoin="round"
              aria-hidden="true"
            >
              <path d="M3 16.5v2.25A2.25 2.25 0 0 0 5.25 21h13.5A2.25 2.25 0 0 0 21 18.75V16.5M16.5 12 12 16.5m0 0L7.5 12m4.5 4.5V3" />
            </svg>
          ) : undefined
        }
        trailingIcon={
          <svg
            className={`transition-transform ${open ? "rotate-180" : ""}`}
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth={2}
            strokeLinecap="round"
            strokeLinejoin="round"
            aria-hidden="true"
          >
            <path d="m6 9 6 6 6-6" />
          </svg>
        }
      >
        Export
      </Button>

      {open && (
        <div
          role="menu"
          aria-label="Export SBOM format"
          onKeyDown={handleMenuKeyDown}
          className="absolute right-0 top-full z-40 mt-1 min-w-[180px] rounded-md border border-[var(--color-border)] bg-[var(--color-surface)] p-1 shadow-lg"
        >
          {FORMATS.map((fmt, i) => (
            <button
              key={fmt}
              ref={(el) => {
                itemRefs.current[i] = el
              }}
              type="button"
              role="menuitem"
              tabIndex={i === activeIndex ? 0 : -1}
              onClick={() => handleSelect(fmt)}
              className="flex w-full items-center gap-2 rounded px-3 py-2 text-left text-xs text-[var(--color-text-primary)] transition-colors hover:bg-[var(--color-surface-raised)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)]"
            >
              <span className="font-mono text-2xs text-[var(--color-text-tertiary)]">.{FORMAT_EXT[fmt].split(".").pop()}</span>
              <span>{FORMAT_LABELS[fmt]}</span>
            </button>
          ))}
        </div>
      )}
    </div>
  )
}
