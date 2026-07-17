export function KpiCard({
  label,
  value,
  note,
  valueClass,
  onClick,
}: {
  label: string
  value: string
  note: string
  valueClass: string
  onClick?: () => void
}) {
  const base =
    "flex flex-col rounded-md border border-[var(--color-border)] bg-[var(--color-surface-raised)] px-5 py-4 text-left"
  const body = (
    <>
      <p className="font-mono text-2xs font-semibold uppercase tracking-[0.16em] text-[var(--color-text-tertiary)]">
        {label}
      </p>
      <p className={`mt-3 text-[28px] font-semibold leading-none tabular-nums tracking-[-0.02em] ${valueClass}`}>{value}</p>
      <p className="mt-2 text-xs text-[var(--color-text-secondary)]">{note}</p>
    </>
  )

  // Only a card with a real handler is interactive — otherwise render a plain
  // div so it doesn't advertise clickability or steal a tab stop.
  if (!onClick) {
    return <div className={base}>{body}</div>
  }
  return (
    <button
      type="button"
      onClick={onClick}
      className={`${base} cursor-pointer transition-colors hover:border-[var(--color-accent)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)]`}
    >
      {body}
    </button>
  )
}
