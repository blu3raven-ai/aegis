
export function CollapsibleGroupHeader({
  label,
  count,
  isExpanded,
  onToggle,
  colSpan,
  checkboxSlot,
}: {
  label: string
  count: number
  isExpanded: boolean
  onToggle: () => void
  colSpan: number
  checkboxSlot?: React.ReactNode
}) {
  return (
    <tr
      className="cursor-pointer border-b border-[var(--color-border)] bg-[var(--color-surface-raised)] transition-colors hover:brightness-110"
      onClick={onToggle}
    >
      {checkboxSlot && (
        <td className="w-8 px-2 py-2.5" onClick={(e) => e.stopPropagation()}>
          {checkboxSlot}
        </td>
      )}
      <td colSpan={checkboxSlot ? colSpan - 1 : colSpan} className="px-2.5 py-2.5">
        <div className="flex items-center gap-2.5">
          <svg
            className={`h-4 w-4 shrink-0 text-[var(--color-text-secondary)] transition-transform duration-200 ${isExpanded ? "rotate-90" : ""}`}
            viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round"
          >
            <polyline points="9 18 15 12 9 6" />
          </svg>
          <span className="font-semibold text-sm text-[var(--color-text-primary)]">{label}</span>
          <span className="rounded-md bg-[var(--color-surface)] px-2 py-0.5 text-xs font-semibold tabular-nums text-[var(--color-text-secondary)]">
            {count}
          </span>
        </div>
      </td>
    </tr>
  )
}
