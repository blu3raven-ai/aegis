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
          <span className="shrink-0 font-[family-name:var(--font-jetbrains-mono)] font-semibold text-[var(--color-text-primary)]">{label}</span>
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
        className="overflow-x-auto overflow-y-auto rounded-b-xl border border-[var(--color-border)] bg-slate-100 dark:bg-slate-950"
        style={{ maxHeight }}
      >
        <table className="w-full border-collapse">
          <tbody>
            {lines.map((line) => {
              const isHighlighted =
                line.highlighted === true ||
                (highlightRange != null &&
                  line.number >= highlightRange.start &&
                  line.number <= highlightRange.end)
              return (
                <tr
                  key={line.number}
                  className={isHighlighted ? "bg-orange-500/15 text-orange-700 dark:text-orange-100" : ""}
                >
                  <td className="w-9 select-none whitespace-nowrap py-[1px] pl-2 pr-3 text-right align-top font-[family-name:var(--font-jetbrains-mono)] text-[10px] leading-relaxed text-[var(--color-text-secondary)]/35">
                    {line.number}
                  </td>
                  <td className="py-[1px] pr-3 align-top">
                    <pre className="font-[family-name:var(--font-jetbrains-mono)] text-[11px] leading-relaxed whitespace-pre text-slate-700 dark:text-slate-300">
                      {line.content || " "}
                    </pre>
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>
    </div>
  )
}
