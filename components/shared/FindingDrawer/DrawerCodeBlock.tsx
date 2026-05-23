// components/shared/FindingDrawer/DrawerCodeBlock.tsx

export function DrawerCodeBlock({
  lines,
  highlightRange,
  metaBar,
  maxHeight = 620,
}: {
  lines: { number: number; content: string; highlighted?: boolean }[]
  highlightRange?: { start: number; end: number }
  metaBar: { label: string; filePath: string; lineRange?: string }
  maxHeight?: number
}) {
  return (
    <div>
      <div className="flex items-center justify-between gap-2 rounded-t-xl border border-b-0 border-[var(--color-border)] bg-[var(--color-surface-raised)] px-3 py-1.5 text-xs text-[var(--color-text-secondary)]">
        <span className="flex min-w-0 items-center gap-1.5 overflow-hidden">
          <span className="shrink-0">{metaBar.label}</span>
          <span className="shrink-0 opacity-40">·</span>
          <span
            className="min-w-0 truncate font-[family-name:var(--font-jetbrains-mono)]"
            title={metaBar.filePath}
          >
            {metaBar.filePath}
          </span>
        </span>
        {metaBar.lineRange && (
          <span className="shrink-0">{metaBar.lineRange}</span>
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
                  <span className="mr-5 inline-block w-12 select-none text-right font-[family-name:var(--font-jetbrains-mono)] text-[var(--color-text-secondary)]">
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
