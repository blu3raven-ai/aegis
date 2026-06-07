"use client"

import { useEffect, useRef, useState } from "react"
import type { SbomFormat } from "@/lib/client/sbom-api"

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
  const ref = useRef<HTMLDivElement>(null)

  useEffect(() => {
    function handleClick(e: MouseEvent) {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false)
    }
    document.addEventListener("mousedown", handleClick)
    return () => document.removeEventListener("mousedown", handleClick)
  }, [])

  function handleSelect(fmt: SbomFormat) {
    setOpen(false)
    const safeName = repoName.replace(/[^a-z0-9_.-]/gi, "-").toLowerCase()
    onExport(fmt, `${safeName}.${FORMAT_EXT[fmt]}`)
  }

  return (
    <div ref={ref} className="relative">
      <button
        type="button"
        disabled={loading}
        onClick={() => setOpen((prev) => !prev)}
        className="flex items-center gap-1.5 rounded-lg border border-[var(--color-border)] bg-[var(--color-surface)] px-3 py-1.5 text-xs font-medium text-[var(--color-text-secondary)] transition-colors hover:bg-[var(--color-surface-raised)] hover:text-[var(--color-text-primary)] disabled:cursor-not-allowed disabled:opacity-40 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)]"
        aria-haspopup="true"
        aria-expanded={open}
      >
        {loading ? (
          <svg
            className="h-3.5 w-3.5 animate-spin"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth={2}
            aria-hidden="true"
          >
            <path d="M12 2v4m0 12v4M4.93 4.93l2.83 2.83m8.48 8.48 2.83 2.83M2 12h4m12 0h4M4.93 19.07l2.83-2.83m8.48-8.48 2.83-2.83" />
          </svg>
        ) : (
          <svg
            className="h-3.5 w-3.5"
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
        )}
        Export
        <svg
          className={`h-3 w-3 text-[var(--color-text-tertiary)] transition-transform ${open ? "rotate-180" : ""}`}
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
      </button>

      {open && (
        <div className="absolute right-0 top-full z-40 mt-1 min-w-[180px] rounded-xl border border-[var(--color-border)] bg-[var(--color-surface)] p-1 shadow-lg">
          {(Object.keys(FORMAT_LABELS) as SbomFormat[]).map((fmt) => (
            <button
              key={fmt}
              type="button"
              onClick={() => handleSelect(fmt)}
              className="flex w-full items-center gap-2 rounded-lg px-3 py-2 text-left text-xs text-[var(--color-text-primary)] transition-colors hover:bg-[var(--color-surface-raised)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)]"
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
