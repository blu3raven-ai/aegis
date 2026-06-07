// components/shared/FindingDrawer/DrawerCodeBlock.tsx
import React from "react"
import { DrawerCodeLines } from "./DrawerCodeLines"

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
          <span className="shrink-0 font-[family-name:var(--font-jetbrains-mono)] font-semibold text-[var(--color-text-primary)]">{label}</span>
          {filePath && (
            <>
              <span className="shrink-0 opacity-40">·</span>
              <span
                className="min-w-0 truncate font-[family-name:var(--font-jetbrains-mono)] font-semibold text-[var(--color-text-primary)]"
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
      <div className="overflow-hidden rounded-b-xl border border-[var(--color-border)] bg-slate-100 dark:bg-slate-950">
        <DrawerCodeLines
          code={lines.map((l) => l.content).join("\n")}
          startLine={lines[0]?.number ?? 1}
          highlightIdx={
            highlightRange != null
              ? lines.findIndex((l) => l.number >= highlightRange.start && l.number <= highlightRange.end)
              : lines.findIndex((l) => l.highlighted === true)
          }
          borderCls="border-[var(--color-border)]"
          maxHeight={maxHeight}
        />
      </div>
    </div>
  )
}
