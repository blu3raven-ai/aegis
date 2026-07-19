import { LineChart } from "lucide-react"
import { useId } from "react"
import { Card } from "@/components/ui/Card"

interface ChartEmptyStateProps {
  /** Chart heading, kept identical to the populated chart so the card doesn't shift. */
  title: string
  /** One-line explanation of why the chart is empty. */
  message: string
}

// A dimmed placeholder curve — shape only, no real data. Decorative, so it is
// aria-hidden and the message carries the meaning for assistive tech.
const GHOST_CURVE = [58, 54, 60, 51, 47, 53, 45, 49, 43, 47, 41, 44]

/** Empty state for a trend chart: a ghosted preview curve behind a centered
 *  message, so an un-populated analytics card still reads as an instrument
 *  rather than bare text. */
export function ChartEmptyState({ title, message }: ChartEmptyStateProps) {
  const gradId = `chart-empty-${useId().replace(/:/g, "")}`
  const W = 800
  const H = 176
  const PAD_B = 20
  const usable = H - PAD_B
  const max = 66
  const min = 38
  const range = max - min
  const step = W / (GHOST_CURVE.length - 1)
  const yOf = (v: number) => usable - ((v - min) / range) * (usable - 12) - 6
  const line = GHOST_CURVE.map(
    (v, i) => `${i === 0 ? "M" : "L"}${(step * i).toFixed(1)},${yOf(v).toFixed(1)}`,
  ).join(" ")
  const area = `${line} L${W},${usable} L0,${usable} Z`

  return (
    <Card className="rounded-md">
      <h2 className="font-mono text-[11px] font-semibold uppercase tracking-[0.22em] text-[var(--color-text-secondary)]">{title}</h2>
      <div className="relative mt-3">
        <svg
          viewBox={`0 0 ${W} ${H}`}
          className="h-44 w-full opacity-30"
          preserveAspectRatio="none"
          aria-hidden="true"
        >
          <defs>
            <linearGradient id={gradId} x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="var(--color-accent)" stopOpacity="0.35" />
              <stop offset="100%" stopColor="var(--color-accent)" stopOpacity="0" />
            </linearGradient>
          </defs>
          <g stroke="var(--color-border)" strokeWidth="1">
            <line x1="0" y1={usable * 0.33} x2={W} y2={usable * 0.33} strokeDasharray="2 5" />
            <line x1="0" y1={usable * 0.66} x2={W} y2={usable * 0.66} strokeDasharray="2 5" />
          </g>
          <path d={area} fill={`url(#${gradId})`} />
          <path
            d={line}
            fill="none"
            stroke="var(--color-text-tertiary)"
            strokeWidth="1.5"
            strokeDasharray="5 5"
            vectorEffect="non-scaling-stroke"
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center gap-2 text-center">
          <LineChart className="h-6 w-6 text-[var(--color-text-tertiary)]" aria-hidden="true" />
          <p className="max-w-xs text-sm text-[var(--color-text-secondary)]">{message}</p>
        </div>
      </div>
    </Card>
  )
}
