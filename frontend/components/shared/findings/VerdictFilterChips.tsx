"use client"

import { useRef, type KeyboardEvent, type ReactNode } from "react"
import { FilterChip } from "@/components/ui/FilterChip"
import type { VerdictFilter } from "@/lib/shared/findings/verdicts"

type Counts = {
  total: number
  confirmed: number
  needs_runtime_verification?: number
  needs_verify: number
  possible: number
  ruled_out: number
  legacy: number
}

type Chip = { value: VerdictFilter; label: string; glyph?: ReactNode }

// Small severity-toned glyphs. Token-driven so light + dark themes pick up
// the right contrast without per-chip overrides. Decorative — aria-hidden
// at the FilterChip slot since the chip label already carries the meaning.
const GLYPH_CLASS = "h-2.5 w-2.5 shrink-0"

const GlyphDot = ({ className }: { className: string }) => (
  <svg aria-hidden viewBox="0 0 10 10" className={`${GLYPH_CLASS} ${className}`}>
    <circle cx="5" cy="5" r="4" fill="currentColor" />
  </svg>
)

const GlyphRing = ({ className }: { className: string }) => (
  <svg aria-hidden viewBox="0 0 10 10" className={`${GLYPH_CLASS} ${className}`} fill="none" stroke="currentColor" strokeWidth="1.5">
    <circle cx="5" cy="5" r="3.5" />
  </svg>
)

const GlyphBolt = ({ className }: { className: string }) => (
  <svg aria-hidden viewBox="0 0 10 10" className={`${GLYPH_CLASS} ${className}`} fill="currentColor">
    <path d="M5.5 0L1.5 6h2.5l-1 4 5-6H5.5z" />
  </svg>
)

const GlyphCheck = ({ className }: { className: string }) => (
  <svg
    aria-hidden
    viewBox="0 0 10 10"
    className={`${GLYPH_CLASS} ${className}`}
    fill="none"
    stroke="currentColor"
    strokeWidth="2"
    strokeLinecap="round"
    strokeLinejoin="round"
  >
    <path d="M2 5l2 2 4-5" />
  </svg>
)

const CHIPS: Chip[] = [
  { value: null, label: "All open" },
  { value: "confirmed", label: "Confirmed", glyph: <GlyphDot className="text-[var(--color-severity-critical-text)]" /> },
  { value: "needs_runtime_verification", label: "Needs runtime check", glyph: <GlyphDot className="text-[var(--color-severity-high-text)]" /> },
  { value: "needs_verify", label: "Needs verify", glyph: <GlyphDot className="text-[var(--color-severity-medium-text)]" /> },
  { value: "possible", label: "Possible", glyph: <GlyphRing className="text-[var(--color-text-tertiary)]" /> },
  { value: "legacy", label: "Legacy", glyph: <GlyphBolt className="text-[var(--color-state-deferred)]" /> },
  { value: "ruled_out", label: "Ruled out", glyph: <GlyphCheck className="text-[var(--color-status-ok-text)]" /> },
]

function countFor(c: Counts | undefined, v: VerdictFilter): number {
  if (!c) return 0
  if (v === null) {
    return (
      (c.confirmed ?? 0) +
      (c.needs_runtime_verification ?? 0) +
      (c.needs_verify ?? 0) +
      (c.possible ?? 0) +
      (c.legacy ?? 0)
    )
  }
  if (v === "all") return c.total ?? 0
  return c[v as keyof Counts] ?? 0
}

interface VerdictFilterChipsProps {
  active: VerdictFilter
  counts: Counts | undefined
  onChange: (next: VerdictFilter) => void
}

export function VerdictFilterChips({
  active,
  counts,
  onChange,
}: VerdictFilterChipsProps) {
  const groupRef = useRef<HTMLDivElement>(null)

  function onKeyDown(e: KeyboardEvent<HTMLDivElement>) {
    if (e.key !== "ArrowRight" && e.key !== "ArrowLeft") return
    const buttons = Array.from(
      groupRef.current?.querySelectorAll<HTMLButtonElement>("button") ?? [],
    )
    const i = buttons.findIndex((b) => b === document.activeElement)
    if (i === -1) return
    e.preventDefault()
    const next =
      e.key === "ArrowRight"
        ? (i + 1) % buttons.length
        : (i - 1 + buttons.length) % buttons.length
    buttons[next].focus()
  }

  return (
    <div
      ref={groupRef}
      role="group"
      aria-label="Filter findings by verdict"
      onKeyDown={onKeyDown}
      className="flex flex-wrap gap-2"
    >
      {CHIPS.map((chip) => {
        const isActive = active === chip.value
        const count = countFor(counts, chip.value)
        return (
          <FilterChip
            key={String(chip.value)}
            active={isActive}
            count={count}
            onClick={() => onChange(chip.value)}
            label={
              <span className="inline-flex items-center gap-1.5">
                {chip.glyph}
                <span className="whitespace-nowrap">{chip.label}</span>
              </span>
            }
          />
        )
      })}
    </div>
  )
}
