import type { SecretFinding } from "@/lib/shared/secrets/types"
import { AGE_BUCKETS, findingAgeDays } from "@/lib/shared/secrets/dashboard-utils"

const BUCKET_COLORS = [
  { color: "var(--color-status-ok)", gradientTop: "#6ee7b7" },
  { color: "var(--color-severity-medium)", gradientTop: "#fcd34d" },
  { color: "var(--color-severity-high)", gradientTop: "#fdba74" },
  { color: "var(--color-severity-critical)", gradientTop: "#fca5a5" },
  { color: "var(--color-severity-critical)", gradientTop: "var(--color-severity-critical)" },
]

export function OrgAgeBucketsChart({
  findings,
  onSelectAgeBucket,
}: {
  findings: SecretFinding[]
  onSelectAgeBucket?: (bucket: string) => void
}) {
  const active = findings.filter((f) => f.reviewStatus === "new" || f.reviewStatus === "confirmed")
  const now = Date.now()
  const bucketCounts = AGE_BUCKETS.map(() => 0)

  for (const finding of active) {
    const days = findingAgeDays(finding, now)
    if (days === null) continue
    const idx = AGE_BUCKETS.findIndex((b) => days >= b.minDays && days < b.maxDays)
    if (idx !== -1) bucketCounts[idx] += 1
  }

  const total = bucketCounts.reduce((s, v) => s + v, 0)

  if (total === 0) {
    return (
      <div className="rounded-2xl border border-dashed border-[var(--color-border)] p-6 text-sm text-[var(--color-text-secondary)]">
        No age data to display yet.
      </div>
    )
  }

  const maxCount = Math.max(1, ...bucketCounts)
  const gridMax = Math.max(4, Math.ceil(maxCount / 4) * 4)
  const gridLines = Array.from({ length: 5 }, (_, i) => Math.round((gridMax / 4) * i))

  const CHART_W = 480
  const PAD = { top: 36, right: 16, bottom: 60, left: 32 }
  const plotW = CHART_W - PAD.left - PAD.right
  const plotH = 160
  const CHART_H = PAD.top + plotH + PAD.bottom
  const barGroupW = plotW / AGE_BUCKETS.length
  const barW = Math.min(barGroupW * 0.52, 56)

  return (
    <div className="flex flex-col" style={{ height: "320px" }}>
      <div className="flex items-center justify-between">
        <span className="text-xs text-[var(--color-text-secondary)] opacity-60">
          {onSelectAgeBucket ? "Click a bar to filter Review" : ""}
        </span>
        <span className="rounded-full border border-[var(--color-border)] bg-[var(--color-surface-raised)] px-3 py-1 text-xs font-medium text-[var(--color-text-secondary)]">
          {total} confirmed
        </span>
      </div>

      <svg
        viewBox={`0 0 ${CHART_W} ${CHART_H}`}
        className="w-full flex-1"
        preserveAspectRatio="xMidYMid meet"
        role="img"
        aria-label="Confirmed findings by age bucket"
      >
        <defs>
          {BUCKET_COLORS.map((b, i) => (
            <linearGradient key={i} id={`age-grad-${i}`} x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor={b.gradientTop} stopOpacity="0.9" />
              <stop offset="100%" stopColor={b.color} stopOpacity="1" />
            </linearGradient>
          ))}
        </defs>

        {/* Grid lines + y-axis labels */}
        {gridLines.map((v) => {
          const y = PAD.top + plotH - (v / gridMax) * plotH
          return (
            <g key={v}>
              <line
                x1={PAD.left} y1={y} x2={PAD.left + plotW} y2={y}
                stroke="var(--color-border)" strokeWidth="1" strokeDasharray="4 3"
              />
              <text x={PAD.left - 6} y={y + 4} textAnchor="end" fontSize="10" fill="var(--color-text-secondary)">
                {v}
              </text>
            </g>
          )
        })}

        {/* Bars */}
        {AGE_BUCKETS.map((bucket, i) => {
          const { color } = BUCKET_COLORS[i]
          const count = bucketCounts[i]
          const barH = Math.max(count > 0 ? 4 : 0, (count / gridMax) * plotH)
          const cx = PAD.left + barGroupW * i + barGroupW / 2
          const x = cx - barW / 2
          const y = PAD.top + plotH - barH
          const pct = total > 0 ? Math.round((count / total) * 100) : 0
          const clickable = onSelectAgeBucket && count > 0

          return (
            <g key={bucket.label}>
              {count > 0 ? (
                <g
                  onClick={() => clickable && onSelectAgeBucket(bucket.label)}
                  style={{ cursor: clickable ? "pointer" : "default" }}
                >
                  <rect
                    x={x} y={y} width={barW} height={barH} rx="6"
                    fill={`url(#age-grad-${i})`}
                    className={clickable ? "transition-opacity hover:opacity-80" : ""}
                  />
                  {/* Invisible larger hit area */}
                  {clickable && (
                    <rect x={x - 8} y={y - 8} width={barW + 16} height={barH + 8} fill="transparent" />
                  )}
                </g>
              ) : (
                <rect x={x} y={PAD.top + plotH - 3} width={barW} height={3} rx="1.5"
                  fill="var(--color-border)" opacity="0.5" />
              )}

              {/* Count label */}
              {count > 0 && (
                <text x={cx} y={y - 7} textAnchor="middle" fontSize="12" fontWeight="700" fill={color}>
                  {count}
                </text>
              )}

              {/* Bucket label */}
              <text x={cx} y={PAD.top + plotH + 16} textAnchor="middle" fontSize="11" fill="var(--color-text-secondary)">
                {bucket.label}
              </text>

              {/* Percentage */}
              <text x={cx} y={PAD.top + plotH + 32} textAnchor="middle" fontSize="10" fill="var(--color-text-secondary)" opacity="0.7">
                {pct}%
              </text>
            </g>
          )
        })}
      </svg>
    </div>
  )
}
