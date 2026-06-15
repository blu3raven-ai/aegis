"use client"

import { useState, useRef, useEffect } from "react"
import { buildFindingsExportUrl, type FindingExportFilters } from "@/lib/client/exports-api"
import { Button } from "@/components/ui/Button"

interface ExportFindingsButtonProps {
  /** Active filters from the findings page — forwarded to the export URL. */
  filters?: FindingExportFilters
}

/**
 * Toolbar button that opens a small dropdown to choose CSV or JSONL export.
 * Clicking a format triggers a browser file download by navigating to the
 * streaming export endpoint — no JS buffering required.
 */
export function ExportFindingsButton({ filters = {} }: ExportFindingsButtonProps) {
  const [open, setOpen] = useState(false)
  const containerRef = useRef<HTMLDivElement>(null)

  // Close the dropdown when the user clicks outside of it.
  useEffect(() => {
    if (!open) return
    function handleOutsideClick(e: MouseEvent) {
      if (containerRef.current && !containerRef.current.contains(e.target as Node)) {
        setOpen(false)
      }
    }
    document.addEventListener("mousedown", handleOutsideClick)
    return () => document.removeEventListener("mousedown", handleOutsideClick)
  }, [open])

  function handleExport(format: "csv" | "json") {
    const url = buildFindingsExportUrl(filters, format)
    const a = document.createElement("a")
    a.href = url
    a.download = ""
    a.click()
    setOpen(false)
  }

  return (
    <div ref={containerRef} className="relative">
      <Button
        variant="secondary"
        size="sm"
        onClick={() => setOpen((v) => !v)}
        aria-haspopup="true"
        aria-expanded={open}
        leadingIcon={
          <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth={1.75} strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
            <path d="M8 2v8M5 7l3 3 3-3M3 13h10" />
          </svg>
        }
        trailingIcon={
          <svg className={`transition-transform ${open ? "rotate-180" : ""}`} viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
            <path d="M4 6l4 4 4-4" />
          </svg>
        }
      >
        Export
      </Button>

      {open && (
        <div
          role="menu"
          className="absolute right-0 z-20 mt-1.5 w-36 overflow-hidden rounded-lg border border-[var(--color-border)] bg-[var(--color-surface)] shadow-lg"
        >
          <button
            type="button"
            role="menuitem"
            onClick={() => handleExport("csv")}
            className="flex w-full items-center gap-2 px-3 py-2 text-xs font-medium text-[var(--color-text-primary)] hover:bg-[var(--color-bg-hover)] transition-colors"
          >
            <span className="font-[family-name:var(--font-jetbrains-mono)] text-2xs text-[var(--color-text-tertiary)] w-10">CSV</span>
            Spreadsheet
          </button>
          <div className="h-px bg-[var(--color-border-divider)]" />
          <button
            type="button"
            role="menuitem"
            onClick={() => handleExport("json")}
            className="flex w-full items-center gap-2 px-3 py-2 text-xs font-medium text-[var(--color-text-primary)] hover:bg-[var(--color-bg-hover)] transition-colors"
          >
            <span className="font-[family-name:var(--font-jetbrains-mono)] text-2xs text-[var(--color-text-tertiary)] w-10">JSONL</span>
            Newline JSON
          </button>
        </div>
      )}
    </div>
  )
}
