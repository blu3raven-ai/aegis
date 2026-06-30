"use client"

import { useId } from "react"

export interface SparklineProps {
  /** Series values, oldest → newest. Renders nothing if fewer than two. */
  values: number[] | null
  /** Line colour — a CSS colour or `var(--token)`. */
  stroke: string
  /** Size classes for the svg. Defaults to a compact inline spark. */
  className?: string
  /** Soft gradient area under the line (fades to transparent). */
  withArea?: boolean
}

const W = 80
const H = 24
const PAD = 2

function linePath(values: number[]): string {
  const min = Math.min(...values)
  const max = Math.max(...values)
  const range = max - min || 1
  const step = W / (values.length - 1)
  return values
    .map((v, i) => {
      const x = i * step
      const y = H - PAD - ((v - min) / range) * (H - PAD * 2)
      return `${i === 0 ? "M" : "L"}${x.toFixed(1)},${y.toFixed(1)}`
    })
    .join(" ")
}

/** Compact inline trend line — a glanceable micro-chart with no axes or labels.
 *  The stroke is non-scaling so it stays 1.5px crisp when stretched to fill. */
export function Sparkline({ values, stroke, className = "h-6 w-20", withArea = false }: SparklineProps) {
  // Sanitised: useId() returns colon-bearing ids that break SVG url(#…) refs.
  const gradId = `spark-${useId().replace(/:/g, "")}`
  if (!values || values.length < 2) return null
  const line = linePath(values)
  const area = `${line} L${W},${H} L0,${H} Z`
  return (
    <svg viewBox={`0 0 ${W} ${H}`} className={className} preserveAspectRatio="none" aria-hidden="true">
      {withArea && (
        <>
          <defs>
            <linearGradient id={gradId} x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor={stroke} stopOpacity="0.28" />
              <stop offset="100%" stopColor={stroke} stopOpacity="0" />
            </linearGradient>
          </defs>
          <path d={area} fill={`url(#${gradId})`} />
        </>
      )}
      <path
        d={line}
        fill="none"
        stroke={stroke}
        strokeWidth="1.5"
        strokeLinecap="round"
        strokeLinejoin="round"
        vectorEffect="non-scaling-stroke"
      />
    </svg>
  )
}
