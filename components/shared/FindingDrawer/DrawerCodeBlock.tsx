// components/shared/FindingDrawer/DrawerCodeBlock.tsx
import React from "react"

export function DrawerCodeBlock({
  lines,
  highlightRange,
  label,
  filePath,
  lineRange,
  maxHeight = 620,
}: {
  lines: { number: number; content: string; highlighted?: boolean }[]
  highlightRange?: { start: number; end: number }
  label: string
  filePath?: string
  lineRange?: React.ReactNode
  maxHeight?: number
}) {
  return (
    <div>
      <div className="flex items-center justify-between gap-2 rounded-t-xl border border-b-0 border-[var(--color-border)] bg-[var(--color-surface-raised)] px-3 py-1.5 text-xs text-[var(--color-text-secondary)]">
        <span className="flex min-w-0 items-center gap-1.5 overflow-hidden">
          <span className="shrink-0">{label}</span>
          {filePath && (
            <>
              <span className="shrink-0 opacity-40">·</span>
              <span
                className="min-w-0 truncate font-[family-name:var(--font-jetbrains-mono)]"
                title={filePath}
              >
                {filePath}
              </span>
            </>
          )}
        </span>
        {lineRange && (
          <span className="shrink-0">{lineRange}</span>
        )}
      </div>
      <div
        className="overflow-auto rounded-b-xl border border-[var(--color-border)] bg-slate-100 dark:bg-slate-950"
        style={{ maxHeight }}
      >
        <pre className="min-w-max p-4 text-sm leading-6 text-slate-700 dark:text-slate-300">
          <code>
            {lines.map((line) => {
              const isHighlighted =
                line.highlighted === true ||
                (highlightRange != null &&
                  line.number >= highlightRange.start &&
                  line.number <= highlightRange.end)
              return (
                <span
                  key={line.number}
                  className={`block ${isHighlighted ? "-mx-4 bg-orange-500/15 px-4 text-orange-700 dark:text-orange-100" : ""}`}
                >
                  <span className="inline-block w-9 select-none pl-1 pr-3 text-right font-[family-name:var(--font-jetbrains-mono)] text-[10px] text-[var(--color-text-secondary)]/40">
                    {line.number}
                  </span>
                  <span>{line.content || " "}</span>
                </span>
              )
            })}
          </code>
        </pre>
      </div>
    </div>
  )
}
